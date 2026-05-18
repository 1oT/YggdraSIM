# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP profile applicator: walks a decoded pySim profile document and writes each PE to the simulated FS."""
from __future__ import annotations

import ctypes
import io
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

from SIMCARD.etsi_fs import ISIM_AID, USIM_AID
from SIMCARD.saip_pysim_specs import (
    FcpAttributes,
    GfmEntry,
    apply_pysim_augmentations,
    apply_pysim_service_table_overlay_to_inspector,
    decode_fcp_attributes,
    pysim_alias_specs_for,
    pysim_gfm_walk,
    pysim_normalize_aka_decoded,
    pysim_pe_wrapper,
    pysim_sd_keys,
)

# When pySim is installed, use its TS-aligned service-name maps
# in place of the inspector's hand-curated copies. The call is a no-op
# in stripped deployments without pySim.
apply_pysim_service_table_overlay_to_inspector()
from SIMCARD.state import (
    SimProfileAuthConfig,
    SimProfileFsNode,
    SimProfileImage,
    SimProfilePinEntry,
    SimProfilePukEntry,
    SimProfileRfmInstance,
    SimProfileSecurityDomain,
    SimProfileSecurityDomainKey,
)
from SIMCARD.utils import decode_imsi_ef, encode_iccid_ef, encode_imsi_ef, read_tlv

_SAIP_ASN1 = None
_SAIP_ASN1_FAILED = False

# pySim's SAIP ASN.1 decoder can loop for an unbounded amount of time on
# malformed or pathological ProfileElement payloads (see asn1tools DER
# decoder ``decode_content`` in ``codecs/der.py``). That hang has been
# observed to wedge the simulator in the middle of ``STORE DATA`` while
# processing the final ``A3`` member of a LoadBoundProfilePackage, which
# blocks the APDU response and leaks memory because the DER decoder keeps
# appending entries to an inner list on every iteration. Keep a short
# per-element budget so a bad element is skipped rather than stalling the
# whole install; operators that specifically need the heavy decode to run
# can raise the budget via the env var below.
_SAIP_DECODE_TIMEOUT_ENV = "YGGDRASIM_SIM_SAIP_DECODE_TIMEOUT_SECONDS"
_SAIP_DECODE_DEFAULT_TIMEOUT = 2.5


def _resolve_saip_decode_timeout_seconds() -> float:
    raw_value = str(os.environ.get(_SAIP_DECODE_TIMEOUT_ENV, "") or "").strip()
    if len(raw_value) == 0:
        return _SAIP_DECODE_DEFAULT_TIMEOUT
    try:
        parsed = float(raw_value)
    except ValueError:
        return _SAIP_DECODE_DEFAULT_TIMEOUT
    if parsed <= 0.0:
        return _SAIP_DECODE_DEFAULT_TIMEOUT
    return parsed


# Grace period after the soft deadline during which the worker thread is
# polled for a cooperative exit. If it is still alive when the grace
# period elapses, we escalate to an async-exception injection (see
# ``_stop_runaway_decode_thread``).
_SAIP_DECODE_WORKER_GRACE_SECONDS = 1.0


def _stop_runaway_decode_thread(worker: threading.Thread) -> None:
    """Force a looping ``asn1tools`` decoder thread to unwind.

    The pathological path in ``asn1tools`` stays in pure-Python bytecode
    inside the DER ``decode_content`` loop, so ``PyThreadState_SetAsyncExc``
    is reliable at breaking it. We raise ``SystemExit`` rather than a
    ``BaseException`` subclass so any lingering references held by the
    decoder's local list are dropped promptly and the several-GB memory
    growth observed on repeated installs is avoided. If the ctypes entry
    point is unavailable (extremely stripped interpreter) we simply give
    up and let the daemon thread die with the process; we never want the
    fallback to itself wedge the simulator.
    """
    if worker.is_alive() is False:
        return
    thread_id = worker.ident
    if thread_id is None:
        return
    try:
        set_async_exc = ctypes.pythonapi.PyThreadState_SetAsyncExc
    except AttributeError:
        return
    set_async_exc.argtypes = (ctypes.c_ulong, ctypes.py_object)
    set_async_exc.restype = ctypes.c_int
    # The first call delivers SystemExit to the worker. If it happens to be
    # stuck in a C extension call at that exact moment the runtime will not
    # honour the async exception until it returns to Python bytecode; asn1tools
    # is implemented in Python so the common case completes immediately.
    delivered = set_async_exc(ctypes.c_ulong(thread_id), ctypes.py_object(SystemExit))
    if delivered == 0:
        return
    if delivered > 1:
        # PyThreadState_SetAsyncExc returns the number of threads affected;
        # >1 means we accidentally hit more than one thread with the same
        # ident (can only happen if we raced with thread teardown). Undo the
        # delivery so we don't leak SystemExit into an unrelated thread.
        set_async_exc(ctypes.c_ulong(thread_id), ctypes.c_long(0))
        return
    # Give the worker a short, bounded window to unwind after the exception
    # is queued; we must not block the install path indefinitely.
    deadline = time.monotonic() + _SAIP_DECODE_WORKER_GRACE_SECONDS
    while worker.is_alive() and time.monotonic() < deadline:
        time.sleep(0.05)


def _decode_profile_element_bounded(
    asn1: Any,
    raw_tlv: bytes,
    timeout_seconds: float,
) -> tuple[Any, dict[str, Any]] | None:
    """Execute ``asn1.decode('ProfileElement', raw_tlv)`` under a hard deadline.

    Returns the ``(pe_type, decoded)`` tuple on success, or ``None`` on
    timeout / exception. When the deadline elapses the worker thread is
    actively killed via ``PyThreadState_SetAsyncExc`` so the asn1 decoder
    state (including the unbounded inner list that caused the original
    multi-GB leak) is released promptly instead of being held for the
    remainder of the process lifetime.
    """
    result_slot: list[Any] = [None]
    exc_slot: list[BaseException | None] = [None]

    def _worker() -> None:
        try:
            result_slot[0] = asn1.decode("ProfileElement", raw_tlv)
        except BaseException as error:
            exc_slot[0] = error

    worker = threading.Thread(
        target=_worker,
        name="saip-profile-element-decode",
        daemon=True,
    )
    worker.start()
    worker.join(timeout=max(0.5, float(timeout_seconds)))
    if worker.is_alive():
        _stop_runaway_decode_thread(worker)
        return None
    if exc_slot[0] is not None:
        return None
    return result_slot[0]


# ---------------------------------------------------------------------------
# Native ProfileElement salvage
#
# When ``asn1tools`` cannot decode a ``ProfileElement`` (either because it
# hits the DER ``decode_content`` infinite loop or raises on a malformed
# inner TLV), we still want to extract the file contents that the SIM
# simulator needs at runtime. The walkers below implement a hand-rolled
# DER parser driven by a table of SAIP ``ProfileElement`` alternatives; for
# every file-based section (PE-MF, PE-CD, PE-TELECOM, PE-USIM, PE-OPT-USIM,
# PE-ISIM, PE-OPT-ISIM, PE-PHONEBOOK, PE-GSM-ACCESS, PE-CSIM, PE-OPT-CSIM,
# PE-EAP, PE-DF-5GS, PE-DF-SAIP, PE-DF-SNPN, PE-DF-5GPROSE) the walker
# recovers every ``File`` slot declared in the schema even when asn1tools
# stalls on a pathological sibling.
#
# The hybrid IoT sections (PE-IoT / PE-OPT-IoT) are intentionally omitted:
# their SEQUENCE fields interleave files from multiple parent containers
# (MF + ADF.USIM + DF.5GS + DF.SAIP), which the flat
# ``_consume_profile_element`` dispatch path cannot express without a
# per-field parent override table. Operators that install IoT Minimal
# profiles must rely on the asn1tools path until that refactor lands.
#
# References:
#   * pySim ``esim/asn1/saip/PE_Definitions-3.3.1.asn`` (AUTOMATIC TAGS,
#     IMPLICIT by default, EXTENSIBILITY IMPLIED) — the canonical schema.
#   * 3GPP TS 31.102 / TS 31.103 / TS 51.011 / ETSI TS 102 221 for file
#     identifiers and per-EF record structures.
#   * ``Tools/ProfilePackage/saip_asn1_decode._EF_KEY_TO_FID`` for the
#     authoritative token-to-FID mapping used by the rest of the tool.
# ---------------------------------------------------------------------------


def _decode_asn1_tag_number(tag_bytes: bytes) -> tuple[int, int, bool]:
    """Return ``(class_code, tag_number, constructed)`` from a BER/DER tag.

    ``class_code`` follows ITU-T X.690 section 8.1.2.2:
    0=universal, 1=application, 2=context-specific, 3=private.
    ``tag_number`` is the decoded long-form value when the low five bits
    of the first byte are all set; otherwise it is the literal low five
    bits. ``constructed`` reflects bit 6 of the first byte.
    """
    if len(tag_bytes) == 0:
        raise ValueError("Empty ASN.1 tag.")
    first = tag_bytes[0]
    class_code = (first >> 6) & 0x03
    constructed = bool(first & 0x20)
    low_five = first & 0x1F
    if low_five != 0x1F:
        return class_code, low_five, constructed
    number = 0
    continuation_seen = False
    for byte in tag_bytes[1:]:
        continuation_seen = True
        number = (number << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            return class_code, number, constructed
    if continuation_seen is False:
        raise ValueError("Long-form tag missing continuation bytes.")
    raise ValueError("Long-form tag is not terminated.")


# ProfileElement CHOICE member index → outer tag bytes. AUTOMATIC TAGS
# IMPLICIT encodes context-specific constructed alternatives as 0xA0 + N
# for single-byte tags (N < 31) and as ``BF <N>`` for long-form tags
# (N >= 31). The mapping below covers the whole CHOICE and is used both
# by the dispatcher below and by the regression tests that assert every
# file-based section has a matching section spec.
_PE_CHOICE_OUTER_TAGS: dict[int, bytes] = {}
for _choice_index in range(0, 256):
    if _choice_index < 31:
        _PE_CHOICE_OUTER_TAGS[_choice_index] = bytes([0xA0 + _choice_index])
        continue
    if _choice_index < 0x80:
        _PE_CHOICE_OUTER_TAGS[_choice_index] = bytes([0xBF, _choice_index])
        continue
    # Long-form tags >= 128 would need multi-byte base-128 encoding; the
    # current SAIP schema does not use any and we stop the precomputation
    # once we hit that boundary rather than emit bogus bytes.
    break
del _choice_index


# PE section schemas: outer tag bytes → {pe_type, fields}. ``pe_type`` is
# the key used by ``_SECTION_SPECS`` / ``_consume_profile_element`` and
# matches the asn1tools member name. ``fields`` maps the AUTOMATIC TAGS
# SEQUENCE field index (starting at 0) to the asn1tools-style field name
# that the rest of the pipeline expects in the decoded dict.
#
# Every section here is a pure "file" section whose SEQUENCE members are
# either metadata (``*-header`` / ``templateID``) or ``File`` types. The
# salvage walker produces a ``{field_name: bytes}`` dict that is shape-
# compatible with the asn1tools-success path.
_PE_SECTION_SCHEMAS: dict[bytes, dict[str, Any]] = {
    # PE-MF → [16]
    _PE_CHOICE_OUTER_TAGS[16]: {
        "pe_type": "mf",
        "fields": {
            0: "mf-header",
            1: "templateID",
            2: "mf",
            3: "ef-pl",
            4: "ef-iccid",
            5: "ef-dir",
            6: "ef-arr",
            7: "ef-umpc",
        },
    },
    # PE-CD → [17]
    _PE_CHOICE_OUTER_TAGS[17]: {
        "pe_type": "cd",
        "fields": {
            0: "cd-header",
            1: "templateID",
            2: "df-cd",
            3: "ef-launchpad",
            4: "ef-icon",
        },
    },
    # PE-TELECOM → [18]
    _PE_CHOICE_OUTER_TAGS[18]: {
        "pe_type": "telecom",
        "fields": {
            0: "telecom-header",
            1: "templateID",
            2: "df-telecom",
            3: "ef-arr",
            4: "ef-rma",
            5: "ef-sume",
            6: "ef-ice-dn",
            7: "ef-ice-ff",
            8: "ef-psismsc",
            9: "df-graphics",
            10: "ef-img",
            11: "ef-iidf",
            12: "ef-ice-graphics",
            13: "ef-launch-scws",
            14: "ef-icon",
            15: "df-phonebook",
            16: "ef-pbr",
            17: "ef-ext1",
            18: "ef-aas",
            19: "ef-gas",
            20: "ef-psc",
            21: "ef-cc",
            22: "ef-puid",
            23: "ef-iap",
            24: "ef-adn",
            25: "ef-pbc",
            26: "ef-anr",
            27: "ef-puri",
            28: "ef-email",
            29: "ef-sne",
            30: "ef-uid",
            31: "ef-grp",
            32: "ef-ccp1",
            33: "df-multimedia",
            34: "ef-mml",
            35: "ef-mmdf",
            36: "df-mmss",
            37: "ef-mlpl",
            38: "ef-mspl",
            39: "ef-mmssmode",
            40: "df-mcs",
            41: "ef-mst",
            42: "ef-mcs-config",
            43: "df-v2x",
            44: "ef-vst",
            45: "ef-v2x-config",
            46: "ef-v2xp-pc5",
            47: "ef-v2xp-Uu",
        },
    },
    # PE-USIM → [19]
    _PE_CHOICE_OUTER_TAGS[19]: {
        "pe_type": "usim",
        "fields": {
            0: "usim-header",
            1: "templateID",
            2: "adf-usim",
            3: "ef-imsi",
            4: "ef-arr",
            5: "ef-keys",
            6: "ef-keysPS",
            7: "ef-hpplmn",
            8: "ef-ust",
            9: "ef-fdn",
            10: "ef-sms",
            11: "ef-smsp",
            12: "ef-smss",
            13: "ef-spn",
            14: "ef-est",
            15: "ef-start-hfn",
            16: "ef-threshold",
            17: "ef-psloci",
            18: "ef-acc",
            19: "ef-fplmn",
            20: "ef-loci",
            21: "ef-ad",
            22: "ef-ecc",
            23: "ef-netpar",
            24: "ef-epsloci",
            25: "ef-epsnsc",
        },
    },
    # PE-OPT-USIM → [20]
    _PE_CHOICE_OUTER_TAGS[20]: {
        "pe_type": "opt-usim",
        "fields": {
            0: "optusim-header",
            1: "templateID",
            2: "ef-li",
            3: "ef-acmax",
            4: "ef-acm",
            5: "ef-gid1",
            6: "ef-gid2",
            7: "ef-msisdn",
            8: "ef-puct",
            9: "ef-cbmi",
            10: "ef-cbmid",
            11: "ef-sdn",
            12: "ef-ext2",
            13: "ef-ext3",
            14: "ef-cbmir",
            15: "ef-plmnwact",
            16: "ef-oplmnwact",
            17: "ef-hplmnwact",
            18: "ef-dck",
            19: "ef-cnl",
            20: "ef-smsr",
            21: "ef-bdn",
            22: "ef-ext5",
            23: "ef-ccp2",
            24: "ef-ext4",
            25: "ef-acl",
            26: "ef-cmi",
            27: "ef-ici",
            28: "ef-oci",
            29: "ef-ict",
            30: "ef-oct",
            31: "ef-vgcs",
            32: "ef-vgcss",
            33: "ef-vbs",
            34: "ef-vbss",
            35: "ef-emlpp",
            36: "ef-aaem",
            37: "ef-hiddenkey",
            38: "ef-pnn",
            39: "ef-opl",
            40: "ef-mbdn",
            41: "ef-ext6",
            42: "ef-mbi",
            43: "ef-mwis",
            44: "ef-cfis",
            45: "ef-ext7",
            46: "ef-spdi",
            47: "ef-mmsn",
            48: "ef-ext8",
            49: "ef-mmsicp",
            50: "ef-mmsup",
            51: "ef-mmsucp",
            52: "ef-nia",
            53: "ef-vgcsca",
            54: "ef-vbsca",
            55: "ef-gbabp",
            56: "ef-msk",
            57: "ef-muk",
            58: "ef-ehplmn",
            59: "ef-gbanl",
            60: "ef-ehplmnpi",
            61: "ef-lrplmnsi",
            62: "ef-nafkca",
            63: "ef-spni",
            64: "ef-pnni",
            65: "ef-ncp-ip",
            66: "ef-ufc",
            67: "ef-nasconfig",
            68: "ef-uicciari",
            69: "ef-pws",
            70: "ef-fdnuri",
            71: "ef-bdnuri",
            72: "ef-sdnuri",
            73: "ef-ial",
            74: "ef-ips",
            75: "ef-ipd",
            76: "ef-epdgid",
            77: "ef-epdgselection",
            78: "ef-epdgidem",
            79: "ef-epdgselectionem",
            80: "ef-frompreferred",
            81: "ef-imsconfigdata",
            82: "ef-3gpppsdataoff",
            83: "ef-3gpppsdataoffservicelist",
            84: "ef-xcapconfigdata",
            85: "ef-earfcnlist",
            86: "ef-mudmidconfigdata",
            87: "ef-eaka",
        },
    },
    # PE-ISIM → [21]
    _PE_CHOICE_OUTER_TAGS[21]: {
        "pe_type": "isim",
        "fields": {
            0: "isim-header",
            1: "templateID",
            2: "adf-isim",
            3: "ef-impi",
            4: "ef-impu",
            5: "ef-domain",
            6: "ef-ist",
            7: "ef-ad",
            8: "ef-arr",
        },
    },
    # PE-OPT-ISIM → [22]
    _PE_CHOICE_OUTER_TAGS[22]: {
        "pe_type": "opt-isim",
        "fields": {
            0: "optisim-header",
            1: "templateID",
            2: "ef-pcscf",
            3: "ef-sms",
            4: "ef-smsp",
            5: "ef-smss",
            6: "ef-smsr",
            7: "ef-gbabp",
            8: "ef-gbanl",
            9: "ef-nafkca",
            10: "ef-uicciari",
            11: "ef-frompreferred",
            12: "ef-imsconfigdata",
            13: "ef-xcapconfigdata",
            14: "ef-webrtcuri",
            15: "ef-mudmidconfigdata",
        },
    },
    # PE-PHONEBOOK → [23]
    _PE_CHOICE_OUTER_TAGS[23]: {
        "pe_type": "phonebook",
        "fields": {
            0: "phonebook-header",
            1: "templateID",
            2: "df-phonebook",
            3: "ef-pbr",
            4: "ef-ext1",
            5: "ef-aas",
            6: "ef-gas",
            7: "ef-psc",
            8: "ef-cc",
            9: "ef-puid",
            10: "ef-iap",
            11: "ef-adn",
            12: "ef-pbc",
            13: "ef-anr",
            14: "ef-puri",
            15: "ef-email",
            16: "ef-sne",
            17: "ef-uid",
            18: "ef-grp",
            19: "ef-ccp1",
        },
    },
    # PE-GSM-ACCESS → [24]
    _PE_CHOICE_OUTER_TAGS[24]: {
        "pe_type": "gsm-access",
        "fields": {
            0: "gsm-access-header",
            1: "templateID",
            2: "df-gsm-access",
            3: "ef-kc",
            4: "ef-kcgprs",
            5: "ef-cpbcch",
            6: "ef-invscan",
        },
    },
    # PE-CSIM → [25]
    _PE_CHOICE_OUTER_TAGS[25]: {
        "pe_type": "csim",
        "fields": {
            0: "csim-header",
            1: "templateID",
            2: "adf-csim",
            3: "ef-arr",
            4: "ef-call-count",
            5: "ef-imsi-m",
            6: "ef-imsi-t",
            7: "ef-tmsi",
            8: "ef-ah",
            9: "ef-aop",
            10: "ef-aloc",
            11: "ef-cdmahome",
            12: "ef-znregi",
            13: "ef-snregi",
            14: "ef-distregi",
            15: "ef-accolc",
            16: "ef-term",
            17: "ef-acp",
            18: "ef-prl",
            19: "ef-ruimid",
            20: "ef-csim-st",
            21: "ef-spc",
            22: "ef-otapaspc",
            23: "ef-namlock",
            24: "ef-ota",
            25: "ef-sp",
            26: "ef-esn-meid-me",
            27: "ef-li",
            28: "ef-usgind",
            29: "ef-ad",
            30: "ef-max-prl",
            31: "ef-spcs",
            32: "ef-mecrp",
            33: "ef-home-tag",
            34: "ef-group-tag",
            35: "ef-specific-tag",
            36: "ef-call-prompt",
        },
    },
    # PE-OPT-CSIM → [26]
    _PE_CHOICE_OUTER_TAGS[26]: {
        "pe_type": "opt-csim",
        "fields": {
            0: "optcsim-header",
            1: "templateID",
            2: "ef-ssci",
            3: "ef-fdn",
            4: "ef-sms",
            5: "ef-smsp",
            6: "ef-smss",
            7: "ef-ssfc",
            8: "ef-spn",
            9: "ef-mdn",
            10: "ef-ecc",
            11: "ef-me3gpdopc",
            12: "ef-3gpdopm",
            13: "ef-sipcap",
            14: "ef-mipcap",
            15: "ef-sipupp",
            16: "ef-mipupp",
            17: "ef-sipsp",
            18: "ef-mipsp",
            19: "ef-sippapss",
            20: "ef-puzl",
            21: "ef-maxpuzl",
            22: "ef-hrpdcap",
            23: "ef-hrpdupp",
            24: "ef-csspr",
            25: "ef-atc",
            26: "ef-eprl",
            27: "ef-bcsmscfg",
            28: "ef-bcsmspref",
            29: "ef-bcsmstable",
            30: "ef-bcsmsp",
            31: "ef-bakpara",
            32: "ef-upbakpara",
            33: "ef-mmsn",
            34: "ef-ext8",
            35: "ef-mmsicp",
            36: "ef-mmsup",
            37: "ef-mmsucp",
            38: "ef-auth-capability",
            39: "ef-3gcik",
            40: "ef-dck",
            41: "ef-gid1",
            42: "ef-gid2",
            43: "ef-cdmacnl",
            44: "ef-sf-euimid",
            45: "ef-est",
            46: "ef-hidden-key",
            47: "ef-lcsver",
            48: "ef-lcscp",
            49: "ef-sdn",
            50: "ef-ext2",
            51: "ef-ext3",
            52: "ef-ici",
            53: "ef-oci",
            54: "ef-ext5",
            55: "ef-ccp2",
            56: "ef-applabels",
            57: "ef-model",
            58: "ef-rc",
            59: "ef-smscap",
            60: "ef-mipflags",
            61: "ef-3gpduppext",
            62: "ef-ipv6cap",
            63: "ef-tcpconfig",
            64: "ef-dgc",
            65: "ef-wapbrowsercp",
            66: "ef-wapbrowserbm",
            67: "ef-mmsconfig",
            68: "ef-jdl",
        },
    },
    # PE-EAP → [27]
    _PE_CHOICE_OUTER_TAGS[27]: {
        "pe_type": "eap",
        "fields": {
            0: "eap-header",
            1: "templateID",
            2: "df-eap",
            3: "ef-eapkeys",
            4: "ef-eapstatus",
            5: "ef-puid",
            6: "ef-ps",
            7: "ef-curid",
            8: "ef-reid",
            9: "ef-realm",
        },
    },
    # PE-DF-5GS → [28]
    _PE_CHOICE_OUTER_TAGS[28]: {
        "pe_type": "df-5gs",
        "fields": {
            0: "df-5gs-header",
            1: "templateID",
            2: "df-df-5gs",
            3: "ef-5gs3gpploci",
            4: "ef-5gsn3gpploci",
            5: "ef-5gs3gppnsc",
            6: "ef-5gsn3gppnsc",
            7: "ef-5gauthkeys",
            8: "ef-uac-aic",
            9: "ef-suci-calc-info",
            10: "ef-opl5g",
            11: "ef-supinai",
            12: "ef-routing-indicator",
            13: "ef-ursp",
            14: "ef-tn3gppsnn",
            15: "ef-cag",
            16: "ef-sor-cmci",
            17: "ef-dri",
            18: "ef-5gsedrx",
            19: "ef-5gnswo-conf",
            20: "ef-mchpplmn",
            21: "ef-kausf-derivation",
        },
    },
    # PE-DF-SAIP → [29]
    _PE_CHOICE_OUTER_TAGS[29]: {
        "pe_type": "df-saip",
        "fields": {
            0: "df-saip-header",
            1: "templateID",
            2: "df-df-saip",
            3: "ef-suci-calc-info-usim",
        },
    },
    # PE-DF-SNPN → [30]
    _PE_CHOICE_OUTER_TAGS[30]: {
        "pe_type": "df-snpn",
        "fields": {
            0: "df-snpn-header",
            1: "templateID",
            2: "df-df-snpn",
            3: "ef-pws-snpn",
        },
    },
    # PE-DF-5GPROSE → [31] (long-form tag BF 1F)
    _PE_CHOICE_OUTER_TAGS[31]: {
        "pe_type": "df-5gprose",
        "fields": {
            0: "df-5g-prose-header",
            1: "templateID",
            2: "df-df-5g-prose",
            3: "ef-5g-prose-st",
            4: "ef-5g-prose-dd",
            5: "ef-5g-prose-dc",
            6: "ef-5g-prose-u2nru",
            7: "ef-5g-prose-ru",
            8: "ef-5g-prose-uir",
        },
    },
}


def _collect_file_content_bytes(value_bytes: bytes) -> bytes | None:
    """Extract the concatenated ``fillFileContent`` payload from a File.

    ``File ::= SEQUENCE OF CHOICE { doNotCreate NULL, fileDescriptor Fcp,
    fillFileOffset UInt16, fillFileContent OCTET STRING }``

    AUTOMATIC TAGS assigns the alternatives the context tags ``[0]``
    (``0x80``), ``[1]`` (``0xA1``), ``[2]`` (``0x82``) and ``[3]``
    (``0x83``) respectively. Returns ``None`` when any alternative is
    ``doNotCreate`` (the file is explicitly suppressed), otherwise the
    accumulated bytes with ``fillFileOffset`` treated as an absolute seek
    in the output stream.
    """
    stream = io.BytesIO()
    offset = 0
    while offset < len(value_bytes):
        try:
            child_tag, child_value, _, next_offset = read_tlv(value_bytes, offset)
        except Exception:
            return stream.getvalue()
        if len(child_tag) == 0:
            break
        first = child_tag[0]
        if first == 0x80:
            return None
        if first == 0xA1:
            offset = next_offset
            continue
        if first == 0x82:
            try:
                seek_target = int.from_bytes(child_value, "big", signed=False)
                stream.seek(seek_target, io.SEEK_SET)
            except Exception:
                pass
            offset = next_offset
            continue
        if first == 0x83:
            try:
                stream.write(bytes(child_value))
            except Exception:
                pass
            offset = next_offset
            continue
        offset = next_offset
    return stream.getvalue()


def _salvage_file_profile_element(
    section_schema: dict[str, Any],
    value_bytes: bytes,
) -> dict[str, Any] | None:
    """Generic ``File``-section decoder driven by ``_PE_SECTION_SCHEMAS``.

    Walks the SEQUENCE content inside the outer CHOICE envelope and
    returns a dict keyed by asn1tools-style field names whose values are
    the concatenated ``fillFileContent`` bytes for each ``File`` slot.
    Fields named ``*-header``, ``templateID`` or prefixed with ``df-`` /
    ``adf-`` / ``mf`` are recognised (the section itself still counts as
    salvaged) but do not contribute file bytes. Returns ``None`` only
    when no known slot was recognised, so the caller can skip the
    element entirely rather than emit an empty node.
    """
    fields = section_schema.get("fields") or {}
    if isinstance(fields, dict) is False or len(fields) == 0:
        return None

    decoded: dict[str, Any] = {}
    offset = 0
    produced_any_slot = False
    while offset < len(value_bytes):
        try:
            tag_bytes, field_value, _, next_offset = read_tlv(value_bytes, offset)
        except Exception:
            break
        try:
            class_code, tag_number, constructed = _decode_asn1_tag_number(tag_bytes)
        except Exception:
            offset = next_offset
            continue
        if class_code != 2:
            offset = next_offset
            continue
        field_name = fields.get(tag_number)
        if field_name is None:
            offset = next_offset
            continue

        normalized = str(field_name)
        if normalized.endswith("-header") or normalized == "templateID":
            produced_any_slot = True
            offset = next_offset
            continue

        # Container markers (``mf``, ``df-*``, ``adf-*``) carry an empty
        # File by convention and never have an installable payload; they
        # exist in the schema to advertise the presence of the DF/ADF.
        if (
            normalized == "mf"
            or normalized.startswith("df-")
            or normalized.startswith("adf-")
        ):
            produced_any_slot = True
            offset = next_offset
            continue

        if constructed is False:
            offset = next_offset
            continue

        payload = _collect_file_content_bytes(bytes(field_value))
        if payload is None:
            # ``doNotCreate`` marker – skip without synthesising a node.
            produced_any_slot = True
            offset = next_offset
            continue
        decoded[normalized] = payload
        produced_any_slot = True
        offset = next_offset
    if produced_any_slot is False:
        return None
    return decoded


def _salvage_profile_element_natively(raw_tlv: bytes) -> tuple[str, dict[str, Any]] | None:
    """Dispatch entry for the native ProfileElement salvage path.

    ``raw_tlv`` is the full TLV (tag + length + value) of a single
    ``ProfileElement`` that ``asn1tools`` refused to decode. File-based
    sections listed in ``_PE_SECTION_SCHEMAS`` are walked with
    ``_salvage_file_profile_element``; every other outer tag (including
    non-file sections such as ``header`` / ``pinCodes`` / ``akaParameter``
    and the reserved ``rfu`` slots) returns ``None`` and the element is
    skipped by the caller.
    """
    try:
        outer_tag, outer_value, _, _ = read_tlv(raw_tlv, 0)
    except Exception:
        return None
    if len(outer_tag) == 0:
        return None
    section_schema = _PE_SECTION_SCHEMAS.get(bytes(outer_tag))
    if section_schema is None:
        return None
    decoded = _salvage_file_profile_element(section_schema, bytes(outer_value))
    if decoded is None:
        return None
    return str(section_schema.get("pe_type") or "").strip(), decoded


# Per-section container placement. ``base_path`` is the tuple prefix that
# ``_consume_profile_element`` prepends to every EF name it materialises;
# ``root_path`` (when set) causes the DF/ADF node itself to be emitted so
# the profile image has a clean parent for the EFs. Container FIDs follow
# the SAIP tool's ``_EF_KEY_TO_FID`` convention.
_SECTION_SPECS: dict[str, dict[str, Any]] = {
    "mf": {
        "base_path": ("MF",),
        "root_path": None,
        "root_kind": "",
        "root_fid": "",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "mf",
    },
    "cd": {
        "base_path": ("MF", "DF.CD"),
        "root_path": ("MF", "DF.CD"),
        "root_kind": "df",
        "root_fid": "7F11",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "df-cd",
    },
    "telecom": {
        "base_path": ("MF", "DF.TELECOM"),
        "root_path": ("MF", "DF.TELECOM"),
        "root_kind": "df",
        "root_fid": "7F10",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "df-telecom",
    },
    "phonebook": {
        "base_path": ("MF", "DF.TELECOM", "DF.PHONEBOOK"),
        "root_path": ("MF", "DF.TELECOM", "DF.PHONEBOOK"),
        "root_kind": "df",
        "root_fid": "5F3A",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "df-phonebook",
    },
    "gsm-access": {
        "base_path": ("MF", "ADF.USIM", "DF.GSM-ACCESS"),
        "root_path": ("MF", "ADF.USIM", "DF.GSM-ACCESS"),
        "root_kind": "df",
        "root_fid": "5F3B",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "df-gsm-access",
    },
    "usim": {
        "base_path": ("MF", "ADF.USIM"),
        "root_path": ("MF", "ADF.USIM"),
        "root_kind": "adf",
        "root_fid": "7FF0",
        "root_aid": USIM_AID,
        "root_label": "USIM",
        "descriptor_key": "adf-usim",
    },
    "opt-usim": {
        "base_path": ("MF", "ADF.USIM"),
        "root_path": ("MF", "ADF.USIM"),
        "root_kind": "adf",
        "root_fid": "7FF0",
        "root_aid": USIM_AID,
        "root_label": "USIM",
        "descriptor_key": "adf-usim",
    },
    "isim": {
        "base_path": ("MF", "ADF.ISIM"),
        "root_path": ("MF", "ADF.ISIM"),
        "root_kind": "adf",
        "root_fid": "7FF2",
        "root_aid": ISIM_AID,
        "root_label": "ISIM",
        "descriptor_key": "adf-isim",
    },
    "opt-isim": {
        "base_path": ("MF", "ADF.ISIM"),
        "root_path": ("MF", "ADF.ISIM"),
        "root_kind": "adf",
        "root_fid": "7FF2",
        "root_aid": ISIM_AID,
        "root_label": "ISIM",
        "descriptor_key": "adf-isim",
    },
    "csim": {
        "base_path": ("MF", "ADF.CSIM"),
        "root_path": ("MF", "ADF.CSIM"),
        "root_kind": "adf",
        "root_fid": "7FF3",
        "root_aid": "",
        "root_label": "CSIM",
        "descriptor_key": "adf-csim",
    },
    "opt-csim": {
        "base_path": ("MF", "ADF.CSIM"),
        "root_path": ("MF", "ADF.CSIM"),
        "root_kind": "adf",
        "root_fid": "7FF3",
        "root_aid": "",
        "root_label": "CSIM",
        "descriptor_key": "adf-csim",
    },
    "eap": {
        "base_path": ("MF", "DF.EAP"),
        "root_path": ("MF", "DF.EAP"),
        "root_kind": "df",
        "root_fid": "7F20",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "df-eap",
    },
    "df-5gs": {
        "base_path": ("MF", "ADF.USIM", "DF.5GS"),
        "root_path": ("MF", "ADF.USIM", "DF.5GS"),
        "root_kind": "df",
        "root_fid": "5FC0",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "df-5gs",
    },
    "df-saip": {
        "base_path": ("MF", "ADF.USIM", "DF.SAIP"),
        "root_path": ("MF", "ADF.USIM", "DF.SAIP"),
        "root_kind": "df",
        "root_fid": "5FD0",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "df-saip",
    },
    "df-snpn": {
        "base_path": ("MF", "ADF.USIM", "DF.SNPN"),
        "root_path": ("MF", "ADF.USIM", "DF.SNPN"),
        "root_kind": "df",
        "root_fid": "5FE0",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "df-snpn",
    },
    "df-5gprose": {
        "base_path": ("MF", "ADF.USIM", "DF.5G_PROSE"),
        "root_path": ("MF", "ADF.USIM", "DF.5G_PROSE"),
        "root_kind": "df",
        "root_fid": "5FF0",
        "root_aid": "",
        "root_label": "",
        "descriptor_key": "df-5gprose",
    },
}

# Per-EF file descriptors used by ``_consume_profile_element`` when it
# materialises a ``SimProfileFsNode`` for a recognised file slot. FIDs are
# aligned with ``Tools/ProfilePackage/saip_asn1_decode._EF_KEY_TO_FID`` so
# both the simulator filesystem and the SAIP inspector agree on the
# anchor; where no authoritative FID exists (vendor / reserved entries)
# the file key is intentionally left out so ``_consume_profile_element``
# silently drops it without materialising a bogus node.
#
# ``structure`` values follow the SAIP ``File ::= SEQUENCE OF CHOICE``
# convention: ``linear-fixed`` packs the payload as a single record,
# ``transparent`` stores it as raw data. ``cyclic`` mirrors ``linear-
# fixed`` today; the per-EF record count is inferred by the runtime when
# the profile is activated.
_FILE_SPECS: dict[str, dict[str, Any]] = {
    # MF / housekeeping (TS 102 221 / TS 31.102 Annex H SFIs).
    "ef-iccid": {"name": "EF.ICCID", "fid": "2FE2", "structure": "transparent", "sfi": 0x02},
    "ef-dir": {"name": "EF.DIR", "fid": "2F00", "structure": "linear-fixed", "sfi": 0x1E},
    "ef-pl": {"name": "EF.PL", "fid": "2F05", "structure": "transparent", "sfi": 0x05},
    "ef-arr": {"name": "EF.ARR", "fid": "2F06", "structure": "linear-fixed", "sfi": 0x17},
    "ef-umpc": {"name": "EF.UMPC", "fid": "2F08", "structure": "transparent", "sfi": None},
    # ADF.USIM core (TS 31.102 §4.2).
    "ef-imsi": {"name": "EF.IMSI", "fid": "6F07", "structure": "transparent", "sfi": 0x07},
    "ef-keys": {"name": "EF.KEYS", "fid": "6F08", "structure": "transparent", "sfi": 0x08},
    "ef-keysPS": {"name": "EF.KeysPS", "fid": "6F09", "structure": "transparent", "sfi": None},
    "ef-hpplmn": {"name": "EF.HPPLMN", "fid": "6F31", "structure": "transparent", "sfi": None},
    "ef-ust": {"name": "EF.UST", "fid": "6F38", "structure": "transparent", "sfi": None},
    "ef-spn": {"name": "EF.SPN", "fid": "6F46", "structure": "transparent", "sfi": None},
    "ef-est": {"name": "EF.EST", "fid": "6F56", "structure": "transparent", "sfi": None},
    "ef-start-hfn": {"name": "EF.START-HFN", "fid": "6F5B", "structure": "transparent", "sfi": None},
    "ef-threshold": {"name": "EF.THRESHOLD", "fid": "6F5C", "structure": "transparent", "sfi": None},
    "ef-psloci": {"name": "EF.PSLOCI", "fid": "6F73", "structure": "transparent", "sfi": None},
    "ef-acc": {"name": "EF.ACC", "fid": "6F78", "structure": "transparent", "sfi": None},
    "ef-fplmn": {"name": "EF.FPLMN", "fid": "6F7B", "structure": "transparent", "sfi": None},
    "ef-loci": {"name": "EF.LOCI", "fid": "6F7E", "structure": "transparent", "sfi": None},
    "ef-ad": {"name": "EF.AD", "fid": "6FAD", "structure": "transparent", "sfi": None},
    "ef-ecc": {"name": "EF.ECC", "fid": "6FB7", "structure": "linear-fixed", "sfi": None},
    "ef-netpar": {"name": "EF.NETPAR", "fid": "6FC4", "structure": "transparent", "sfi": None},
    "ef-epsloci": {"name": "EF.EPSLOCI", "fid": "6FE3", "structure": "transparent", "sfi": None},
    "ef-epsnsc": {"name": "EF.EPSNSC", "fid": "6FE4", "structure": "transparent", "sfi": None},
    # ADF.USIM optional (PE-OPT-USIM, TS 31.102 §4.2.x).
    "ef-li": {"name": "EF.LI", "fid": "6F05", "structure": "transparent", "sfi": None},
    "ef-acmax": {"name": "EF.ACMAX", "fid": "6F37", "structure": "transparent", "sfi": None},
    "ef-acm": {"name": "EF.ACM", "fid": "6F39", "structure": "cyclic", "sfi": None},
    "ef-gid1": {"name": "EF.GID1", "fid": "6F3E", "structure": "transparent", "sfi": None},
    "ef-gid2": {"name": "EF.GID2", "fid": "6F3F", "structure": "transparent", "sfi": None},
    "ef-msisdn": {"name": "EF.MSISDN", "fid": "6F40", "structure": "linear-fixed", "sfi": None},
    "ef-puct": {"name": "EF.PUCT", "fid": "6F41", "structure": "transparent", "sfi": None},
    "ef-smsp": {"name": "EF.SMSP", "fid": "6F42", "structure": "linear-fixed", "sfi": None},
    "ef-smss": {"name": "EF.SMSS", "fid": "6F43", "structure": "transparent", "sfi": None},
    "ef-sms": {"name": "EF.SMS", "fid": "6F3C", "structure": "linear-fixed", "sfi": None},
    "ef-cbmi": {"name": "EF.CBMI", "fid": "6F45", "structure": "transparent", "sfi": None},
    "ef-smsr": {"name": "EF.SMSR", "fid": "6F47", "structure": "linear-fixed", "sfi": None},
    "ef-cbmid": {"name": "EF.CBMID", "fid": "6F48", "structure": "transparent", "sfi": None},
    "ef-sdn": {"name": "EF.SDN", "fid": "6F49", "structure": "linear-fixed", "sfi": None},
    "ef-ext1": {"name": "EF.EXT1", "fid": "6F4A", "structure": "linear-fixed", "sfi": None},
    "ef-ext2": {"name": "EF.EXT2", "fid": "6F4B", "structure": "linear-fixed", "sfi": None},
    "ef-ext3": {"name": "EF.EXT3", "fid": "6F4C", "structure": "linear-fixed", "sfi": None},
    "ef-bdn": {"name": "EF.BDN", "fid": "6F4D", "structure": "linear-fixed", "sfi": None},
    "ef-ext5": {"name": "EF.EXT5", "fid": "6F4E", "structure": "linear-fixed", "sfi": None},
    "ef-ccp2": {"name": "EF.CCP2", "fid": "6F4F", "structure": "linear-fixed", "sfi": None},
    "ef-cbmir": {"name": "EF.CBMIR", "fid": "6F50", "structure": "transparent", "sfi": None},
    "ef-ext4": {"name": "EF.EXT4", "fid": "6F55", "structure": "linear-fixed", "sfi": None},
    "ef-acl": {"name": "EF.ACL", "fid": "6F57", "structure": "transparent", "sfi": None},
    "ef-cmi": {"name": "EF.CMI", "fid": "6F58", "structure": "transparent", "sfi": None},
    "ef-adn": {"name": "EF.ADN", "fid": "6F3A", "structure": "linear-fixed", "sfi": None},
    "ef-fdn": {"name": "EF.FDN", "fid": "6F3B", "structure": "linear-fixed", "sfi": None},
    "ef-ccp1": {"name": "EF.CCP1", "fid": "6F3D", "structure": "linear-fixed", "sfi": None},
    "ef-plmnwact": {"name": "EF.PLMNWACT", "fid": "6F60", "structure": "transparent", "sfi": None},
    "ef-oplmnwact": {"name": "EF.OPLMNWACT", "fid": "6F61", "structure": "transparent", "sfi": None},
    "ef-hplmnwact": {"name": "EF.HPLMNWACT", "fid": "6F62", "structure": "transparent", "sfi": None},
    "ef-dck": {"name": "EF.DCK", "fid": "6F2C", "structure": "transparent", "sfi": None},
    "ef-cnl": {"name": "EF.CNL", "fid": "6F32", "structure": "transparent", "sfi": None},
    "ef-ici": {"name": "EF.ICI", "fid": "6F80", "structure": "cyclic", "sfi": None},
    "ef-oci": {"name": "EF.OCI", "fid": "6F81", "structure": "cyclic", "sfi": None},
    "ef-ict": {"name": "EF.ICT", "fid": "6F82", "structure": "cyclic", "sfi": None},
    "ef-oct": {"name": "EF.OCT", "fid": "6F83", "structure": "cyclic", "sfi": None},
    "ef-vgcs": {"name": "EF.VGCS", "fid": "6FB1", "structure": "linear-fixed", "sfi": None},
    "ef-vgcss": {"name": "EF.VGCSS", "fid": "6FB2", "structure": "transparent", "sfi": None},
    "ef-vbs": {"name": "EF.VBS", "fid": "6FB3", "structure": "linear-fixed", "sfi": None},
    "ef-vbss": {"name": "EF.VBSS", "fid": "6FB4", "structure": "transparent", "sfi": None},
    "ef-emlpp": {"name": "EF.EMLPP", "fid": "6FB5", "structure": "transparent", "sfi": None},
    "ef-aaem": {"name": "EF.AAEM", "fid": "6FB6", "structure": "linear-fixed", "sfi": None},
    "ef-hiddenkey": {"name": "EF.HIDDENKEY", "fid": "6FC3", "structure": "transparent", "sfi": None},
    "ef-pnn": {"name": "EF.PNN", "fid": "6FC5", "structure": "linear-fixed", "sfi": None},
    "ef-opl": {"name": "EF.OPL", "fid": "6FC6", "structure": "linear-fixed", "sfi": None},
    "ef-mbdn": {"name": "EF.MBDN", "fid": "6FC7", "structure": "linear-fixed", "sfi": None},
    "ef-ext6": {"name": "EF.EXT6", "fid": "6FC8", "structure": "linear-fixed", "sfi": None},
    "ef-mbi": {"name": "EF.MBI", "fid": "6FC9", "structure": "linear-fixed", "sfi": None},
    "ef-mwis": {"name": "EF.MWIS", "fid": "6FCA", "structure": "linear-fixed", "sfi": None},
    "ef-cfis": {"name": "EF.CFIS", "fid": "6FCB", "structure": "linear-fixed", "sfi": None},
    "ef-ext7": {"name": "EF.EXT7", "fid": "6FCC", "structure": "linear-fixed", "sfi": None},
    "ef-spdi": {"name": "EF.SPDI", "fid": "6FCD", "structure": "transparent", "sfi": None},
    "ef-nia": {"name": "EF.NIA", "fid": "6FD3", "structure": "linear-fixed", "sfi": None},
    "ef-vgcsca": {"name": "EF.VGCSCA", "fid": "6FD4", "structure": "linear-fixed", "sfi": None},
    "ef-vbsca": {"name": "EF.VBSCA", "fid": "6FD2", "structure": "linear-fixed", "sfi": None},
    "ef-gbabp": {"name": "EF.GBABP", "fid": "6FD7", "structure": "transparent", "sfi": None},
    "ef-msk": {"name": "EF.MSK", "fid": "6FD5", "structure": "transparent", "sfi": None},
    "ef-muk": {"name": "EF.MUK", "fid": "6FD6", "structure": "transparent", "sfi": None},
    "ef-ehplmn": {"name": "EF.EHPLMN", "fid": "6FD9", "structure": "transparent", "sfi": None},
    "ef-gbanl": {"name": "EF.GBANL", "fid": "6FDA", "structure": "linear-fixed", "sfi": None},
    "ef-ehplmnpi": {"name": "EF.EHPLMNPI", "fid": "6FDB", "structure": "transparent", "sfi": None},
    "ef-lrplmnsi": {"name": "EF.LRPLMNSI", "fid": "6FDC", "structure": "transparent", "sfi": None},
    "ef-nafkca": {"name": "EF.NAFKCA", "fid": "6FDD", "structure": "linear-fixed", "sfi": None},
    "ef-spni": {"name": "EF.SPNI", "fid": "6FDE", "structure": "transparent", "sfi": None},
    "ef-pws": {"name": "EF.PWS", "fid": "6FEC", "structure": "transparent", "sfi": None},
    "ef-nasconfig": {"name": "EF.NASCONFIG", "fid": "6FE8", "structure": "transparent", "sfi": None},
    "ef-fdnuri": {"name": "EF.FDNURI", "fid": "6FED", "structure": "linear-fixed", "sfi": None},
    "ef-bdnuri": {"name": "EF.BDNURI", "fid": "6FEE", "structure": "linear-fixed", "sfi": None},
    "ef-sdnuri": {"name": "EF.SDNURI", "fid": "6FEF", "structure": "linear-fixed", "sfi": None},
    "ef-ips": {"name": "EF.IPS", "fid": "6FF1", "structure": "transparent", "sfi": None},
    "ef-epdgid": {"name": "EF.EPDGID", "fid": "6FF3", "structure": "transparent", "sfi": None},
    "ef-epdgselection": {
        "name": "EF.EPDGSELECTION",
        "fid": "6FF4",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-frompreferred": {
        "name": "EF.FROMPREFERRED",
        "fid": "6FF7",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-earfcnlist": {
        "name": "EF.EARFCNLIST",
        "fid": "6FFD",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-eaka": {"name": "EF.EAKA", "fid": "6F01", "structure": "transparent", "sfi": None},
    # DF.PHONEBOOK (TS 31.102 §4.4, DF 5F3A).
    "ef-pbr": {"name": "EF.PBR", "fid": "4F30", "structure": "linear-fixed", "sfi": None},
    "ef-iap": {"name": "EF.IAP", "fid": "4F25", "structure": "linear-fixed", "sfi": None},
    "ef-anr": {"name": "EF.ANR", "fid": "4F11", "structure": "linear-fixed", "sfi": None},
    "ef-sne": {"name": "EF.SNE", "fid": "4F19", "structure": "linear-fixed", "sfi": None},
    "ef-email": {"name": "EF.EMAIL", "fid": "4F50", "structure": "linear-fixed", "sfi": None},
    "ef-gas": {"name": "EF.GAS", "fid": "4F4C", "structure": "linear-fixed", "sfi": None},
    "ef-grp": {"name": "EF.GRP", "fid": "4F26", "structure": "linear-fixed", "sfi": None},
    "ef-psc": {"name": "EF.PSC", "fid": "4F22", "structure": "transparent", "sfi": None},
    "ef-cc": {"name": "EF.CC", "fid": "4F23", "structure": "linear-fixed", "sfi": None},
    "ef-puid": {"name": "EF.PUID", "fid": "4F24", "structure": "linear-fixed", "sfi": None},
    "ef-pbc": {"name": "EF.PBC", "fid": "4F09", "structure": "linear-fixed", "sfi": None},
    # DF.GSM-ACCESS (TS 31.102 §4.4.4, DF 5F3B).
    "ef-kc": {"name": "EF.KC", "fid": "4F20", "structure": "transparent", "sfi": None},
    "ef-kcgprs": {"name": "EF.KCGPRS", "fid": "4F52", "structure": "transparent", "sfi": None},
    "ef-cpbcch": {"name": "EF.CPBCCH", "fid": "4F63", "structure": "transparent", "sfi": None},
    "ef-invscan": {"name": "EF.INVSCAN", "fid": "4F64", "structure": "transparent", "sfi": None},
    # DF.5GS (TS 31.102 §4.4.11, DF 5FC0).
    "ef-5gs3gpploci": {
        "name": "EF.5GS3GPPLOCI",
        "fid": "4F01",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-5gsn3gpploci": {
        "name": "EF.5GSN3GPPLOCI",
        "fid": "4F02",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-5gs3gppnsc": {
        "name": "EF.5GS3GPPNSC",
        "fid": "4F03",
        "structure": "linear-fixed",
        "sfi": None,
    },
    "ef-5gsn3gppnsc": {
        "name": "EF.5GSN3GPPNSC",
        "fid": "4F04",
        "structure": "linear-fixed",
        "sfi": None,
    },
    "ef-5gauthkeys": {
        "name": "EF.5GAUTHKEYS",
        "fid": "4F05",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-uac-aic": {
        "name": "EF.UAC-AIC",
        "fid": "4F06",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-suci-calc-info": {
        "name": "EF.SUCI_CALC_INFO",
        "fid": "4F07",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-opl5g": {"name": "EF.OPL5G", "fid": "4F08", "structure": "linear-fixed", "sfi": None},
    "ef-supinai": {"name": "EF.SUPI_NAI", "fid": "4F09", "structure": "transparent", "sfi": None},
    "ef-routing-indicator": {
        "name": "EF.ROUTING-INDICATOR",
        "fid": "4F0A",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-ursp": {"name": "EF.URSP", "fid": "4F0B", "structure": "transparent", "sfi": None},
    "ef-tn3gppsnn": {"name": "EF.TN3GPPSNN", "fid": "4F0C", "structure": "transparent", "sfi": None},
    "ef-cag": {"name": "EF.CAG", "fid": "4F0D", "structure": "transparent", "sfi": None},
    "ef-sor-cmci": {"name": "EF.SOR-CMCI", "fid": "4F0E", "structure": "transparent", "sfi": None},
    "ef-dri": {"name": "EF.DRI", "fid": "4F0F", "structure": "transparent", "sfi": None},
    "ef-5gsedrx": {"name": "EF.5GSEDRX", "fid": "4F10", "structure": "transparent", "sfi": None},
    "ef-5gnswo-conf": {
        "name": "EF.5GNSWO-CONF",
        "fid": "4F11",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-mchpplmn": {"name": "EF.MCHPPLMN", "fid": "4F15", "structure": "transparent", "sfi": None},
    "ef-kausf-derivation": {
        "name": "EF.KAUSF-DERIVATION",
        "fid": "4F16",
        "structure": "transparent",
        "sfi": None,
    },
    # DF.SAIP (TS 31.102 §4.4.10, DF 5FD0).
    "ef-suci-calc-info-usim": {
        "name": "EF.SUCI_CALC_INFO",
        "fid": "4F01",
        "structure": "transparent",
        "sfi": None,
    },
    # ADF.ISIM (TS 31.103 §4.2).
    "ef-impi": {"name": "EF.IMPI", "fid": "6F02", "structure": "transparent", "sfi": None},
    "ef-domain": {"name": "EF.DOMAIN", "fid": "6F03", "structure": "transparent", "sfi": None},
    "ef-impu": {"name": "EF.IMPU", "fid": "6F04", "structure": "linear-fixed", "sfi": None},
    "ef-ist": {"name": "EF.IST", "fid": "6F07", "structure": "transparent", "sfi": None},
    "ef-pcscf": {"name": "EF.PCSCF", "fid": "6F09", "structure": "linear-fixed", "sfi": None},
    "ef-uicciari": {"name": "EF.UICCIARI", "fid": "6FE7", "structure": "transparent", "sfi": None},
    # DF.EAP (TS 31.102 §4.4.x, DF 7F20).
    "ef-eapkeys": {"name": "EF.EAPKEYS", "fid": "4F01", "structure": "transparent", "sfi": None},
    "ef-eapstatus": {
        "name": "EF.EAPSTATUS",
        "fid": "4F02",
        "structure": "transparent",
        "sfi": None,
    },
    # DF.5G_PROSE (TS 31.102 §4.4.13, DF 5FF0).
    "ef-5g-prose-st": {
        "name": "EF.5G-PROSE-ST",
        "fid": "4F01",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-5g-prose-dd": {
        "name": "EF.5G-PROSE-DD",
        "fid": "4F02",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-5g-prose-dc": {
        "name": "EF.5G-PROSE-DC",
        "fid": "4F03",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-5g-prose-u2nru": {
        "name": "EF.5G-PROSE-U2NRU",
        "fid": "4F04",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-5g-prose-ru": {
        "name": "EF.5G-PROSE-RU",
        "fid": "4F05",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-5g-prose-uir": {
        "name": "EF.5G-PROSE-UIR",
        "fid": "4F06",
        "structure": "transparent",
        "sfi": None,
    },
    # DF.SNPN (TS 31.102 §4.4.12, DF 5FE0).
    "ef-pws-snpn": {
        "name": "EF.PWS-SNPN",
        "fid": "4F01",
        "structure": "transparent",
        "sfi": None,
    },
    # ADF.USIM / ADF.ISIM Rel-15/16 IMS configuration (TS 31.103 §4.2,
    # shared with TS 31.102 Annex B.x). MUD/MID and XCAP/IMS/PSDATAOFF
    # are TS 31.102 §4.2.94-§4.2.101.
    "ef-imsconfigdata": {
        "name": "EF.IMSCONFIGDATA",
        "fid": "6FF8",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-xcapconfigdata": {
        "name": "EF.XCAPCONFIGDATA",
        "fid": "6FF9",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-webrtcuri": {
        "name": "EF.WEBRTCURI",
        "fid": "6FFA",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-mudmidconfigdata": {
        "name": "EF.MUDMIDCONFIGDATA",
        "fid": "6FFB",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-3gpppsdataoff": {
        "name": "EF.3GPPPSDATAOFF",
        "fid": "6FFC",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-3gpppsdataoffservicelist": {
        "name": "EF.3GPPPSDATAOFFSERVICELIST",
        "fid": "6FFD",
        "structure": "transparent",
        "sfi": None,
    },
    # ADF.USIM MMS family (TS 51.011 §10.3.51-§10.3.55, TS 31.102 Annex H).
    "ef-mmsn": {"name": "EF.MMSN", "fid": "6FCE", "structure": "linear-fixed", "sfi": None},
    "ef-ext8": {"name": "EF.EXT8", "fid": "6FCF", "structure": "linear-fixed", "sfi": None},
    "ef-mmsicp": {"name": "EF.MMSICP", "fid": "6FD0", "structure": "transparent", "sfi": None},
    "ef-mmsup": {"name": "EF.MMSUP", "fid": "6FD1", "structure": "linear-fixed", "sfi": None},
    # NOTE: EF.MMSUCP (6FD2) collides with EF.VBSCA per legacy SAIP
    # tooling. Leave the canonical FID empty so the node materialises at
    # the right hierarchical path without stomping VBSCA on the same FID.
    "ef-mmsucp": {"name": "EF.MMSUCP", "fid": "", "structure": "transparent", "sfi": None},
    # DF.TELECOM / DF.GRAPHICS (TS 31.102 §4.6.1, SAIP §3.4.4).
    "ef-img": {"name": "EF.IMG", "fid": "4F20", "structure": "linear-fixed", "sfi": None},
    "ef-iidf": {"name": "EF.IIDF", "fid": "4F02", "structure": "transparent", "sfi": None},
    "ef-icon": {"name": "EF.ICON", "fid": "4F01", "structure": "transparent", "sfi": None},
    "ef-launchpad": {
        "name": "EF.LAUNCHPAD",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-launch-scws": {
        "name": "EF.LAUNCH-SCWS",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-ice-dn": {"name": "EF.ICE-DN", "fid": "6FE1", "structure": "linear-fixed", "sfi": None},
    "ef-ice-ff": {"name": "EF.ICE-FF", "fid": "6FE2", "structure": "linear-fixed", "sfi": None},
    "ef-ice-graphics": {
        "name": "EF.ICE-GRAPHICS",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-rma": {"name": "EF.RMA", "fid": "", "structure": "transparent", "sfi": None},
    "ef-sume": {"name": "EF.SUME", "fid": "6F54", "structure": "transparent", "sfi": None},
    # DF.PHONEBOOK (TS 31.102 §4.4.2).
    "ef-aas": {"name": "EF.AAS", "fid": "4F4A", "structure": "linear-fixed", "sfi": None},
    "ef-puri": {"name": "EF.PURI", "fid": "4F4D", "structure": "linear-fixed", "sfi": None},
    "ef-uid": {"name": "EF.UID", "fid": "4F10", "structure": "linear-fixed", "sfi": None},
    # DF.MULTIMEDIA / DF.MMSS / DF.MCS / DF.V2X (SAIP-specific, FIDs are
    # vendor-dependent outside TS 31.102 Annex H). Materialise with a
    # blank FID so the node anchors at the correct hierarchical slot.
    "ef-mml": {"name": "EF.MML", "fid": "", "structure": "linear-fixed", "sfi": None},
    "ef-mmdf": {"name": "EF.MMDF", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mlpl": {"name": "EF.MLPL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mspl": {"name": "EF.MSPL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mmssmode": {"name": "EF.MMSSMODE", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mst": {"name": "EF.MST", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mcs-config": {"name": "EF.MCS-CONFIG", "fid": "", "structure": "transparent", "sfi": None},
    "ef-vst": {"name": "EF.VST", "fid": "", "structure": "transparent", "sfi": None},
    "ef-v2x-config": {
        "name": "EF.V2X-CONFIG",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-v2xp-pc5": {
        "name": "EF.V2XP-PC5",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-v2xp-Uu": {
        "name": "EF.V2XP-UU",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-psismsc": {"name": "EF.PSISMSC", "fid": "6FE5", "structure": "transparent", "sfi": None},
    # OPT-USIM Rel-17/18 extras and misc EFs referenced by SAIP. Some
    # (pnni/ncp-ip/ial/ipd/ufc) do not have a single authoritative FID in
    # TS 31.102 so they carry a blank FID; others align with TS 31.102
    # Annex H assignments.
    "ef-pnni": {"name": "EF.PNNI", "fid": "6FDF", "structure": "linear-fixed", "sfi": None},
    "ef-ncp-ip": {"name": "EF.NCP-IP", "fid": "", "structure": "linear-fixed", "sfi": None},
    "ef-ufc": {"name": "EF.UFC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-ial": {"name": "EF.IAL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-ipd": {"name": "EF.IPD", "fid": "", "structure": "transparent", "sfi": None},
    "ef-epdgidem": {
        "name": "EF.EPDGIDEM",
        "fid": "6FF5",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-epdgselectionem": {
        "name": "EF.EPDGSELECTIONEM",
        "fid": "6FF6",
        "structure": "transparent",
        "sfi": None,
    },
    # PE-EAP additional EFs (SAIP §3.4.13).
    "ef-ps": {"name": "EF.PS", "fid": "", "structure": "transparent", "sfi": None},
    "ef-curid": {"name": "EF.CURID", "fid": "", "structure": "transparent", "sfi": None},
    "ef-reid": {"name": "EF.REID", "fid": "", "structure": "transparent", "sfi": None},
    "ef-realm": {"name": "EF.REALM", "fid": "", "structure": "transparent", "sfi": None},
    # PE-CSIM / PE-OPT-CSIM CDMA entries (3GPP2 C.S0065 / C.S0023).
    # Authoritative FIDs collide with GSM/USIM anchors and require
    # parent-context routing in the SAIP inspector; for the simulator
    # filesystem we anchor them under ADF.CSIM with a blank FID so the
    # node hierarchy is materialised without stomping ADF.USIM files.
    "ef-call-count": {
        "name": "EF.CALL-COUNT",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-imsi-m": {"name": "EF.IMSI-M", "fid": "", "structure": "transparent", "sfi": None},
    "ef-imsi-t": {"name": "EF.IMSI-T", "fid": "", "structure": "transparent", "sfi": None},
    "ef-tmsi": {"name": "EF.TMSI", "fid": "", "structure": "transparent", "sfi": None},
    "ef-ah": {"name": "EF.AH", "fid": "", "structure": "transparent", "sfi": None},
    "ef-aop": {"name": "EF.AOP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-aloc": {"name": "EF.ALOC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-cdmahome": {"name": "EF.CDMAHOME", "fid": "", "structure": "transparent", "sfi": None},
    "ef-znregi": {"name": "EF.ZNREGI", "fid": "", "structure": "transparent", "sfi": None},
    "ef-snregi": {"name": "EF.SNREGI", "fid": "", "structure": "transparent", "sfi": None},
    "ef-distregi": {"name": "EF.DISTREGI", "fid": "", "structure": "transparent", "sfi": None},
    "ef-accolc": {"name": "EF.ACCOLC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-term": {"name": "EF.TERM", "fid": "", "structure": "transparent", "sfi": None},
    "ef-acp": {"name": "EF.ACP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-prl": {"name": "EF.PRL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-ruimid": {"name": "EF.RUIMID", "fid": "", "structure": "transparent", "sfi": None},
    "ef-csim-st": {"name": "EF.CSIM-ST", "fid": "", "structure": "transparent", "sfi": None},
    "ef-spc": {"name": "EF.SPC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-otapaspc": {"name": "EF.OTAPASPC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-namlock": {"name": "EF.NAMLOCK", "fid": "", "structure": "transparent", "sfi": None},
    "ef-ota": {"name": "EF.OTA", "fid": "", "structure": "transparent", "sfi": None},
    "ef-sp": {"name": "EF.SP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-esn-meid-me": {
        "name": "EF.ESN-MEID-ME",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-usgind": {"name": "EF.USGIND", "fid": "", "structure": "transparent", "sfi": None},
    "ef-max-prl": {"name": "EF.MAX-PRL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-spcs": {"name": "EF.SPCS", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mecrp": {"name": "EF.MECRP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-home-tag": {"name": "EF.HOME-TAG", "fid": "", "structure": "transparent", "sfi": None},
    "ef-group-tag": {"name": "EF.GROUP-TAG", "fid": "", "structure": "transparent", "sfi": None},
    "ef-specific-tag": {
        "name": "EF.SPECIFIC-TAG",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-call-prompt": {
        "name": "EF.CALL-PROMPT",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-ssci": {"name": "EF.SSCI", "fid": "", "structure": "transparent", "sfi": None},
    "ef-ssfc": {"name": "EF.SSFC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mdn": {"name": "EF.MDN", "fid": "", "structure": "transparent", "sfi": None},
    "ef-me3gpdopc": {"name": "EF.ME3GPDOPC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-3gpdopm": {"name": "EF.3GPDOPM", "fid": "", "structure": "transparent", "sfi": None},
    "ef-sipcap": {"name": "EF.SIPCAP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mipcap": {"name": "EF.MIPCAP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-sipupp": {"name": "EF.SIPUPP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mipupp": {"name": "EF.MIPUPP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-sipsp": {"name": "EF.SIPSP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mipsp": {"name": "EF.MIPSP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-sippapss": {"name": "EF.SIPPAPSS", "fid": "", "structure": "transparent", "sfi": None},
    "ef-puzl": {"name": "EF.PUZL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-maxpuzl": {"name": "EF.MAXPUZL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-hrpdcap": {"name": "EF.HRPDCAP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-hrpdupp": {"name": "EF.HRPDUPP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-csspr": {"name": "EF.CSSPR", "fid": "", "structure": "transparent", "sfi": None},
    "ef-atc": {"name": "EF.ATC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-eprl": {"name": "EF.EPRL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-bcsmscfg": {"name": "EF.BCSMSCFG", "fid": "", "structure": "transparent", "sfi": None},
    "ef-bcsmspref": {"name": "EF.BCSMSPREF", "fid": "", "structure": "transparent", "sfi": None},
    "ef-bcsmstable": {
        "name": "EF.BCSMSTABLE",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-bcsmsp": {"name": "EF.BCSMSP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-bakpara": {"name": "EF.BAKPARA", "fid": "", "structure": "transparent", "sfi": None},
    "ef-upbakpara": {"name": "EF.UPBAKPARA", "fid": "", "structure": "transparent", "sfi": None},
    "ef-auth-capability": {
        "name": "EF.AUTH-CAPABILITY",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-3gcik": {"name": "EF.3GCIK", "fid": "", "structure": "transparent", "sfi": None},
    "ef-cdmacnl": {"name": "EF.CDMACNL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-sf-euimid": {
        "name": "EF.SF-EUIMID",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-hidden-key": {
        "name": "EF.HIDDEN-KEY",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-lcsver": {"name": "EF.LCSVER", "fid": "", "structure": "transparent", "sfi": None},
    "ef-lcscp": {"name": "EF.LCSCP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-applabels": {"name": "EF.APPLABELS", "fid": "", "structure": "transparent", "sfi": None},
    "ef-model": {"name": "EF.MODEL", "fid": "", "structure": "transparent", "sfi": None},
    "ef-rc": {"name": "EF.RC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-smscap": {"name": "EF.SMSCAP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-mipflags": {"name": "EF.MIPFLAGS", "fid": "", "structure": "transparent", "sfi": None},
    "ef-3gpduppext": {
        "name": "EF.3GPDUPPEXT",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-ipv6cap": {"name": "EF.IPV6CAP", "fid": "", "structure": "transparent", "sfi": None},
    "ef-tcpconfig": {"name": "EF.TCPCONFIG", "fid": "", "structure": "transparent", "sfi": None},
    "ef-dgc": {"name": "EF.DGC", "fid": "", "structure": "transparent", "sfi": None},
    "ef-wapbrowsercp": {
        "name": "EF.WAPBROWSERCP",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-wapbrowserbm": {
        "name": "EF.WAPBROWSERBM",
        "fid": "",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-mmsconfig": {"name": "EF.MMSCONFIG", "fid": "", "structure": "transparent", "sfi": None},
    "ef-jdl": {"name": "EF.JDL", "fid": "", "structure": "transparent", "sfi": None},
}


# Overlay pySim's TCA Profile-Interoperability §9 templates on
# top of the literal table. Augmentation is in-place, FID-anchored
# (parent context preserved) and only fills gaps. The follow-up alias
# pass surfaces pySim spellings (e.g. V2 ``ef-supi-nai``) onto the same
# spec dict so BPPs emitted by pySim-shell or other TCA-compliant
# tooling decode without losing the EF entry.
apply_pysim_augmentations(_FILE_SPECS)


def _install_pysim_aliases(specs: dict[str, dict[str, Any]]) -> None:
    for alias_pe_name, alias_spec in pysim_alias_specs_for(specs).items():
        if alias_pe_name in specs:
            continue
        specs[alias_pe_name] = alias_spec


_install_pysim_aliases(_FILE_SPECS)


def decode_profile_image(
    upp_bytes: bytes,
    *,
    default_iccid: str = "",
    default_name: str = "",
    default_imsi: str = "",
    default_impi: str = "",
) -> SimProfileImage | None:
    """Decode a SAIP profile image byte blob into a structured Python dict."""
    raw = bytes(upp_bytes or b"")
    if len(raw) == 0:
        return None
    image = SimProfileImage(
        profile_name=str(default_name or "").strip(),
        iccid=str(default_iccid or "").strip(),
        imsi=str(default_imsi or "").strip(),
        impi=str(default_impi or "").strip(),
    )

    header_name, header_iccid = _extract_profile_identity_from_header_tlv(raw)
    if len(header_name) > 0:
        image.profile_name = header_name
    if len(header_iccid) > 0:
        image.iccid = header_iccid

    asn1 = _get_saip_asn1()
    if asn1 is None:
        return _finalize_image(image)

    timeout_seconds = _resolve_saip_decode_timeout_seconds()
    offset = 0
    while offset < len(raw):
        try:
            _, _, raw_tlv, next_offset = read_tlv(raw, offset)
        except Exception:
            break
        decode_result = _decode_profile_element_bounded(
            asn1,
            raw_tlv,
            timeout_seconds=timeout_seconds,
        )
        if decode_result is None:
            # Either the decoder raised or blew past the deadline. Try a
            # narrow, hand-rolled walker for the handful of PE sections we
            # know how to salvage (PE-TELECOM in particular, which is the
            # usual asn1tools hang site). If the salvage path also cannot
            # make sense of the bytes, skip the element entirely; the raw
            # UPP is still persisted verbatim so no information is lost.
            salvage = _salvage_profile_element_natively(raw_tlv)
            if salvage is not None:
                salvage_type, salvage_decoded = salvage
                _consume_profile_element(
                    image,
                    str(salvage_type or "").strip(),
                    salvage_decoded,
                )
            offset = next_offset
            continue
        pe_type, decoded = decode_result
        if isinstance(decoded, dict):
            _consume_profile_element(image, str(pe_type or "").strip(), decoded)
        offset = next_offset
    return _finalize_image(image)


def _get_saip_asn1():
    global _SAIP_ASN1, _SAIP_ASN1_FAILED
    if _SAIP_ASN1 is not None:
        return _SAIP_ASN1
    if _SAIP_ASN1_FAILED:
        return None
    try:
        project_root = Path(__file__).resolve().parent.parent
        pysim_root = project_root / "pysim"
        root_text = str(pysim_root)
        if pysim_root.is_dir() and root_text not in sys.path:
            sys.path.insert(0, root_text)
        from pySim.esim import compile_asn1_subdir

        _SAIP_ASN1 = compile_asn1_subdir("saip")
    except Exception:
        _SAIP_ASN1_FAILED = True
        return None
    return _SAIP_ASN1


def _extract_profile_identity_from_header_tlv(profile_bytes: bytes) -> tuple[str, str]:
    try:
        tag_bytes, value, _, _ = read_tlv(profile_bytes, 0)
    except Exception:
        return "", ""
    if tag_bytes != b"\xA0":
        return "", ""

    profile_name = ""
    profile_iccid = ""
    offset = 0
    while offset < len(value):
        try:
            child_tag, child_value, _, next_offset = read_tlv(value, offset)
        except Exception:
            break
        if child_tag == b"\x82" and len(profile_name) == 0:
            try:
                profile_name = bytes(child_value).decode("utf-8", "ignore").strip()
            except Exception:
                profile_name = ""
        elif child_tag == b"\x83" and len(profile_iccid) == 0:
            profile_iccid = bytes(child_value).hex().upper().rstrip("F")
        offset = next_offset
    return profile_name, profile_iccid


def _consume_profile_element(image: SimProfileImage, pe_type: str, decoded: dict[str, Any]) -> None:
    if pe_type == "header":
        profile_name = decoded.get("profileType")
        if isinstance(profile_name, str) and len(profile_name.strip()) > 0:
            image.profile_name = profile_name.strip()
        header_iccid = decoded.get("iccid")
        if isinstance(header_iccid, (bytes, bytearray, memoryview)) and len(header_iccid) > 0:
            image.iccid = bytes(header_iccid).hex().upper().rstrip("F")
        # TCA Profile Interoperability §3.4.2 connectivityParameters.
        # The SAIP header carries an optional TLV stream describing the
        # MNO bearer (BIP / RAM-HTTP). The bytes are kept verbatim so
        # SGP.32 ES10b.GetConnectivityParameters can return them
        # unmodified; conversion to the [1] httpParams OCTET STRING is
        # done by the SGP layer.
        connectivity_value = decoded.get("connectivityParameters")
        if isinstance(connectivity_value, (bytes, bytearray, memoryview)):
            image.connectivity_params_http = bytes(connectivity_value)
        return

    if pe_type == "akaParameter":
        _consume_aka_parameter(image, decoded)
        return

    if pe_type == "pinCodes":
        _consume_pin_codes(image, decoded)
        return

    if pe_type == "pukCodes":
        _consume_puk_codes(image, decoded)
        return

    if pe_type == "securityDomain":
        _consume_security_domain(image, decoded)
        return

    if pe_type == "rfm":
        _consume_rfm(image, decoded)
        return

    if pe_type == "genericFileManagement":
        _consume_generic_file_management(image, decoded)
        return

    spec = _SECTION_SPECS.get(pe_type)
    if spec is None:
        return

    root_descriptor: dict[str, Any] = {}
    descriptor_key = str(spec.get("descriptor_key", "") or "")
    descriptor_present = False
    if len(descriptor_key) > 0 and descriptor_key in decoded:
        root_descriptor = _extract_file_descriptor_dict(decoded.get(descriptor_key))
        descriptor_present = True

    root_path = spec.get("root_path")
    # Optional companion PEs (``opt-usim``/``opt-isim``/``opt-csim``) reuse
    # the same logical container as their mandatory counterpart but never
    # carry a fresh ``adf-*`` descriptor. Emitting a second root node from
    # spec defaults at this point would clobber the AID/FID/lcsi we just
    # learned from the BPP, so skip the root for these companion sections.
    if isinstance(root_path, tuple) and descriptor_present is False and pe_type.startswith("opt-"):
        root_path = None

    if isinstance(root_path, tuple):
        spec_aid = str(spec.get("root_aid", "") or "")
        spec_fid = str(spec.get("root_fid", "") or "")
        bpp_aid_bytes = root_descriptor.get("dfName")
        bpp_fid_bytes = root_descriptor.get("fileID")
        # SAIP TCA Profile Interoperability §3 mandates ``dfName`` for
        # ADF descriptors. Honouring it here lets the runtime FCP/EF.DIR
        # builders emit the AID actually present in the BPP rather than
        # falling back to YggdraSIM's hard-coded test constants.
        resolved_aid = (
            bytes(bpp_aid_bytes).hex().upper()
            if isinstance(bpp_aid_bytes, (bytes, bytearray, memoryview)) and len(bpp_aid_bytes) > 0
            else spec_aid
        )
        resolved_fid = (
            bytes(bpp_fid_bytes).hex().upper()
            if isinstance(bpp_fid_bytes, (bytes, bytearray, memoryview)) and len(bpp_fid_bytes) == 2
            else spec_fid
        )
        lcsi_byte = root_descriptor.get("lcsi")
        lifecycle_state = (
            int(bytes(lcsi_byte)[0])
            if isinstance(lcsi_byte, (bytes, bytearray, memoryview)) and len(lcsi_byte) >= 1
            else 0x05
        )
        image.nodes.append(
            SimProfileFsNode(
                path=root_path,
                name=root_path[-1],
                kind=str(spec.get("root_kind", "df") or "df"),
                fid=resolved_fid,
                aid=resolved_aid,
                label=str(spec.get("root_label", "") or ""),
                lifecycle_state=lifecycle_state,
            )
        )

    base_path = tuple(spec.get("base_path", ("MF",)))
    for key, value in decoded.items():
        if key.endswith("-header") or key == "templateID":
            continue
        if str(key) == descriptor_key:
            continue
        file_spec = _FILE_SPECS.get(str(key))
        if file_spec is None:
            continue
        materialised = _materialize_ef_value(value)
        if materialised is None:
            continue
        payload, ef_descriptor = materialised
        structure = str(file_spec.get("structure", "transparent") or "transparent")
        # FCP-decoder layer: route descriptor parsing through pySim's
        # File.from_fileDescriptor so record_len / efFileSize / lcsi /
        # ARR / fillPattern stay aligned with TS 102 222 + SAIP §5.1.
        attrs = decode_fcp_attributes(ef_descriptor)
        record_length = attrs.record_length
        ef_size = attrs.transparent_size if structure == "transparent" else 0
        if ef_size > 0 and len(payload) < ef_size:
            payload = payload + b"\xFF" * (ef_size - len(payload))
        records: list[bytes] = []
        data = b""
        if structure in ("linear-fixed", "cyclic"):
            if record_length > 0 and len(payload) >= record_length:
                # SAIP §5.1 packs records back-to-back inside ``ef-*``;
                # use the descriptor-supplied length to slice them out
                # so READ RECORD returns the exact bytes from the BPP.
                count = len(payload) // record_length
                records = [
                    payload[i * record_length : (i + 1) * record_length]
                    for i in range(count)
                ]
            elif len(payload) > 0:
                records = [payload]
        else:
            data = payload
        ef_lifecycle = int(attrs.lcsi) if attrs.lcsi is not None else 0x05
        # BPP-supplied SFI overrides are intentionally NOT honoured
        # here: pySim's ``from_fileDescriptor`` stores the raw
        # ``shortEFID`` byte without unpacking the TS 102 221 §13.2
        # SFI bits (bits 7..3), so the value cannot be used as-is.
        # The template-overlay registry already aligns template SFIs with
        # pySim's authoritative TCA Profile-Interoperability §9 maps.
        image.nodes.append(
            SimProfileFsNode(
                path=base_path + (str(file_spec["name"]),),
                name=str(file_spec["name"]),
                kind="ef",
                fid=str(file_spec.get("fid", "") or ""),
                structure=structure,
                data=data,
                records=records,
                sfi=file_spec.get("sfi"),
                lifecycle_state=ef_lifecycle,
                link_path=attrs.link_path,
            )
        )


def _extract_file_descriptor_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        # ``mf-header`` style descriptor objects already arrive as dicts.
        inner = value.get("fileDescriptor") if "fileDescriptor" in value else value
        return inner if isinstance(inner, dict) else value
    if isinstance(value, list) is False:
        return {}
    for item in value:
        if isinstance(item, tuple) is False or len(item) != 2:
            continue
        tag_name = str(item[0] or "").strip()
        if tag_name == "fileDescriptor" and isinstance(item[1], dict):
            return item[1]
    return {}


def _record_length_from_descriptor(descriptor: dict[str, Any]) -> int:
    raw = descriptor.get("fileDescriptor")
    if isinstance(raw, (bytes, bytearray, memoryview)) is False:
        return 0
    body = bytes(raw)
    # ETSI TS 102 221 §11.1.1.4.3: linear-fixed/cyclic descriptor is
    # 5 bytes wide -- byte 0 file descriptor byte, byte 1 data coding,
    # bytes 2-3 record length, byte 4 record count. Anything shorter
    # is a transparent EF descriptor without a record length.
    if len(body) < 4:
        return 0
    return int.from_bytes(body[2:4], "big", signed=False)


def _ef_size_from_descriptor(descriptor: dict[str, Any]) -> int:
    raw = descriptor.get("efFileSize")
    if isinstance(raw, (bytes, bytearray, memoryview)) is False:
        return 0
    body = bytes(raw)
    if len(body) == 0:
        return 0
    return int.from_bytes(body, "big", signed=False)


def _decode_fcp_link_path(descriptor: Any) -> tuple[str, ...]:
    """Decode ``Fcp.linkPath`` (``[PRIVATE 7]`` OCTET STRING, SIZE
    0..8) from a SAIP file descriptor dict.

    SAIP / TCA Profile Interoperability v2.3.1 §8.3.5: the OCTET
    STRING is a concatenation of 2-byte FIDs walking from the MF
    (or the temporary ADF FID when the path is rooted in an ADF)
    down to the file the link points at. An empty OCTET STRING
    denotes "turn this template link file into an independent
    file" (§8.3.5 explicit note). We return the path as a tuple of
    upper-case hex FIDs so consumers can index into a path -> node
    dict without rebuilding hex strings on every lookup.

    Returns an empty tuple when the descriptor is missing or
    malformed; the calling consumer treats that as "no link".
    """
    if isinstance(descriptor, dict) is False:
        return tuple()
    raw = descriptor.get("linkPath")
    if raw is None:
        return tuple()
    if isinstance(raw, (bytes, bytearray, memoryview)) is False:
        return tuple()
    payload = bytes(raw)
    if len(payload) == 0:
        # Per §8.3.5, "an empty linkPath indicates that the link
        # file shall be turned into an independent file." There is
        # no link target so the runtime treats the slot as a
        # regular EF.
        return tuple()
    if len(payload) % 2 != 0:
        # Malformed encoding -- linkPath must be a whole number of
        # FIDs. Drop the link rather than synthesising a partial
        # path that would mis-resolve at runtime.
        return tuple()
    fids: list[str] = []
    for offset in range(0, len(payload), 2):
        fids.append(payload[offset : offset + 2].hex().upper())
    return tuple(fids)


def _consume_pin_codes(image: SimProfileImage, decoded: dict[str, Any]) -> None:
    """SAIP §5.6.1 -- materialise a ``pinCodes`` PE into ``image.pin_codes``.

    Both ``pinconfig`` and ``pinmappings`` choices are tolerated; only the
    former carries actual key material so anything else is dropped silently.
    The retry counter is stored as the high-nibble (max attempts) and
    low-nibble (remaining) of the SAIP ``maxNumOfAttemps-retryNumLeft``
    byte so VERIFY PIN can update both fields independently.

    The decoded dict is routed through pySim's
    ``ProfileElementPin`` wrapper so any future pySim-side
    schema validation surfaces here uniformly. The wrapper is purely
    interpretive -- the local parser remains the authoritative path.
    """
    wrapper = pysim_pe_wrapper("pinCodes", decoded)
    source = getattr(wrapper, "decoded", decoded) if wrapper is not None else decoded
    if isinstance(source, dict) is False:
        source = decoded
    pin_codes_value = source.get("pinCodes")
    if isinstance(pin_codes_value, tuple) is False or len(pin_codes_value) != 2:
        return
    choice_name = str(pin_codes_value[0] or "").strip()
    choice_value = pin_codes_value[1]
    if choice_name != "pinconfig":
        # ``pinmappings`` simply re-binds an existing PIN to another DF
        # and does not provision new key material. Honouring it requires
        # the receiving DF to be in ``image.nodes`` already; defer until
        # the consumer is wired up by a future increment.
        return
    if isinstance(choice_value, list) is False:
        return
    for entry in choice_value:
        if isinstance(entry, dict) is False:
            continue
        try:
            key_reference = int(entry.get("keyReference", 0) or 0) & 0xFF
        except (TypeError, ValueError):
            continue
        pin_value = entry.get("pinValue")
        pin_bytes = bytes(pin_value) if isinstance(pin_value, (bytes, bytearray, memoryview)) else b""
        if len(pin_bytes) == 0:
            continue
        unblock_reference = 0
        try:
            unblock_reference = int(entry.get("unblockingPINReference", 0) or 0) & 0xFF
        except (TypeError, ValueError):
            unblock_reference = 0
        attributes = 0
        try:
            attributes = int(entry.get("pinAttributes", 0) or 0) & 0xFF
        except (TypeError, ValueError):
            attributes = 0
        retry_byte = 0
        try:
            retry_byte = int(entry.get("maxNumOfAttemps-retryNumLeft", 0) or 0) & 0xFF
        except (TypeError, ValueError):
            retry_byte = 0
        max_attempts = (retry_byte >> 4) & 0x0F
        retries_remaining = retry_byte & 0x0F
        if max_attempts == 0:
            max_attempts = 3
        if retries_remaining == 0:
            retries_remaining = max_attempts
        image.pin_codes.append(
            SimProfilePinEntry(
                key_reference=key_reference,
                value=pin_bytes,
                unblock_reference=unblock_reference,
                attributes=attributes,
                max_attempts=max_attempts,
                retries_remaining=retries_remaining,
            )
        )


def _consume_puk_codes(image: SimProfileImage, decoded: dict[str, Any]) -> None:
    """SAIP §5.6.2 -- materialise a ``pukCodes`` PE.

    The PUK retry counter is encoded as the SAIP ``maxNumOfAttemps-
    retryNumLeft`` byte; per TS 102 221 §9.5.4 the unblock counter
    range is [0, 10] so the high/low nibbles each map to a single
    decimal digit -- 0xAA decodes to "10/10 attempts remaining".

    The decoded dict is routed through pySim's ``ProfileElementPuk``
    wrapper for forward-compat with upstream validation.
    """
    wrapper = pysim_pe_wrapper("pukCodes", decoded)
    source = getattr(wrapper, "decoded", decoded) if wrapper is not None else decoded
    if isinstance(source, dict) is False:
        source = decoded
    puk_list = source.get("pukCodes")
    if isinstance(puk_list, list) is False:
        return
    for entry in puk_list:
        if isinstance(entry, dict) is False:
            continue
        try:
            key_reference = int(entry.get("keyReference", 0) or 0) & 0xFF
        except (TypeError, ValueError):
            continue
        puk_value = entry.get("pukValue")
        puk_bytes = bytes(puk_value) if isinstance(puk_value, (bytes, bytearray, memoryview)) else b""
        if len(puk_bytes) == 0:
            continue
        retry_byte = 0
        try:
            retry_byte = int(entry.get("maxNumOfAttemps-retryNumLeft", 0) or 0) & 0xFF
        except (TypeError, ValueError):
            retry_byte = 0
        max_attempts = (retry_byte >> 4) & 0x0F
        retries_remaining = retry_byte & 0x0F
        if max_attempts == 0:
            max_attempts = 10
        if retries_remaining == 0:
            retries_remaining = max_attempts
        # TS 102 221 §9.5.4 caps the PUK counter at 10 attempts; SAIP
        # therefore stores 0xAA = "10/10". Normalise so the runtime
        # ``naa.unblock_chv`` path doesn't see an out-of-range value.
        max_attempts = min(max_attempts, 10)
        retries_remaining = min(retries_remaining, max_attempts)
        image.puk_codes.append(
            SimProfilePukEntry(
                key_reference=key_reference,
                value=puk_bytes,
                max_attempts=max_attempts,
                retries_remaining=retries_remaining,
            )
        )


def _consume_security_domain(image: SimProfileImage, decoded: dict[str, Any]) -> None:
    """SAIP §5.5 -- materialise a ``securityDomain`` PE.

    ``instance`` carries the GP §11.4 application registry tuple
    (instance/class/load-package AID, privileges, lifecycle, install
    parameters). ``keyList`` carries SCP02/SCP03 keys (KeyType +
    KeyData + KeyVersionNumber) plus a derived MAC length per GP
    Card Spec v2.3.1 Amendment D §7.5.

    Key parsing routes through pySim's ``ProfileElementSD`` wrapper
    -- ``SecurityDomainKey.from_saip_dict`` handles the
    ``KeyType`` enum and the ``KeyUsageQualifier`` BitStruct so we
    surface a properly packed usage byte even when the BPP encodes
    the OPTIONAL ``keyUsageQualifier`` as a multi-byte BitStruct.
    The local dict-walker remains as the fallback for unmapped or
    pySim-unsupported shapes.
    """
    wrapper = pysim_pe_wrapper("securityDomain", decoded)
    source = getattr(wrapper, "decoded", decoded) if wrapper is not None else decoded
    if isinstance(source, dict) is False:
        source = decoded
    instance_dict = source.get("instance")
    if isinstance(instance_dict, dict) is False:
        return
    instance_aid_value = instance_dict.get("instanceAID")
    instance_aid_bytes = (
        bytes(instance_aid_value) if isinstance(instance_aid_value, (bytes, bytearray, memoryview)) else b""
    )
    if len(instance_aid_bytes) == 0:
        return
    class_aid_value = instance_dict.get("classAID")
    load_package_aid_value = instance_dict.get("applicationLoadPackageAID")
    privileges_value = instance_dict.get("applicationPrivileges")
    lifecycle_value = instance_dict.get("lifeCycleState")
    install_params_value = instance_dict.get("applicationSpecificParametersC9")
    application_parameters = instance_dict.get("applicationParameters")
    uicc_toolkit_bytes = b""
    if isinstance(application_parameters, dict):
        toolkit_value = application_parameters.get("uiccToolkitApplicationSpecificParametersField")
        if isinstance(toolkit_value, (bytes, bytearray, memoryview)):
            uicc_toolkit_bytes = bytes(toolkit_value)

    sd_keys: list[SimProfileSecurityDomainKey] = []
    key_list = source.get("keyList")
    pysim_keys = pysim_sd_keys(decoded)
    if pysim_keys and isinstance(key_list, list) and len(pysim_keys) == len(key_list):
        # Prefer pySim's typed parse: it collapses the KeyUsageQualifier
        # BitStruct back to a single GP byte and resolves the KeyType
        # enum to the canonical string ahead of the byte-level lookup.
        for raw_entry, pk in zip(key_list, pysim_keys):
            access = 0
            counter_bytes = b""
            if isinstance(raw_entry, dict):
                access = _coerce_byte(raw_entry.get("keyAccess"))
                counter_value = raw_entry.get("keyCounterValue")
                if isinstance(counter_value, (bytes, bytearray, memoryview)):
                    counter_bytes = bytes(counter_value)
            primary_type = 0x00
            primary_data = b""
            primary_mac_length = 8
            if pk.components:
                comp_type, comp_data, mac_len = pk.components[0]
                primary_type = _key_type_string_to_byte(comp_type)
                primary_data = comp_data
                primary_mac_length = mac_len
            sd_keys.append(
                SimProfileSecurityDomainKey(
                    usage_qualifier=pk.key_usage_qualifier,
                    key_identifier=pk.key_identifier,
                    key_version=pk.key_version_number,
                    key_type=primary_type,
                    key_data=primary_data,
                    mac_length=primary_mac_length,
                    counter=counter_bytes,
                    access=access,
                )
            )
    elif isinstance(key_list, list):
        for key_entry in key_list:
            if isinstance(key_entry, dict) is False:
                continue
            usage_qualifier = _coerce_byte(key_entry.get("keyUsageQualifier"))
            key_identifier = _coerce_byte(key_entry.get("keyIdentifier"))
            key_version = _coerce_byte(key_entry.get("keyVersionNumber"))
            access = _coerce_byte(key_entry.get("keyAccess"))
            counter_value = key_entry.get("keyCounterValue")
            counter_bytes = bytes(counter_value) if isinstance(counter_value, (bytes, bytearray, memoryview)) else b""

            components = key_entry.get("keyComponents")
            primary_type = 0x00
            primary_data = b""
            primary_mac_length = 8
            if isinstance(components, list) and len(components) > 0:
                first = components[0]
                if isinstance(first, dict):
                    primary_type = _coerce_byte(first.get("keyType"))
                    component_data = first.get("keyData")
                    if isinstance(component_data, (bytes, bytearray, memoryview)):
                        primary_data = bytes(component_data)
                    try:
                        primary_mac_length = int(first.get("macLength", 8) or 8)
                    except (TypeError, ValueError):
                        primary_mac_length = 8
            sd_keys.append(
                SimProfileSecurityDomainKey(
                    usage_qualifier=usage_qualifier,
                    key_identifier=key_identifier,
                    key_version=key_version,
                    key_type=primary_type,
                    key_data=primary_data,
                    mac_length=primary_mac_length,
                    counter=counter_bytes,
                    access=access,
                )
            )

    perso_data: list[bytes] = []
    perso_value = source.get("sdPersoData")
    if isinstance(perso_value, list):
        for chunk in perso_value:
            if isinstance(chunk, (bytes, bytearray, memoryview)) and len(chunk) > 0:
                perso_data.append(bytes(chunk))

    image.security_domains.append(
        SimProfileSecurityDomain(
            instance_aid=instance_aid_bytes.hex().upper(),
            class_aid=(
                bytes(class_aid_value).hex().upper()
                if isinstance(class_aid_value, (bytes, bytearray, memoryview))
                else ""
            ),
            load_package_aid=(
                bytes(load_package_aid_value).hex().upper()
                if isinstance(load_package_aid_value, (bytes, bytearray, memoryview))
                else ""
            ),
            privileges=(
                bytes(privileges_value)
                if isinstance(privileges_value, (bytes, bytearray, memoryview))
                else b""
            ),
            lifecycle_state=(
                int(bytes(lifecycle_value)[0])
                if isinstance(lifecycle_value, (bytes, bytearray, memoryview)) and len(lifecycle_value) >= 1
                else 0x07
            ),
            install_parameters=(
                bytes(install_params_value)
                if isinstance(install_params_value, (bytes, bytearray, memoryview))
                else b""
            ),
            uicc_toolkit_parameters=uicc_toolkit_bytes,
            keys=sd_keys,
            perso_data=perso_data,
        )
    )


def _consume_rfm(image: SimProfileImage, decoded: dict[str, Any]) -> None:
    """SAIP §5.7 -- materialise an ``rfm`` PE.

    Each PE binds one OTA RFM applet (instance AID + TAR list +
    minimum security level + optional ADF restriction). ETSI TS 102
    226 §8.4 prohibits more than one ADF binding per RFM instance, so
    the optional ``adfRFMAccess`` is materialised verbatim.

    Routes through pySim's ``ProfileElementRFM`` wrapper;
    the wrapper currently does no extra post-decoding but lets future
    upstream invariants surface here without re-touching the parser.
    """
    wrapper = pysim_pe_wrapper("rfm", decoded)
    source = getattr(wrapper, "decoded", decoded) if wrapper is not None else decoded
    if isinstance(source, dict) is False:
        source = decoded
    instance_aid_value = source.get("instanceAID")
    if isinstance(instance_aid_value, (bytes, bytearray, memoryview)) is False:
        return
    instance_aid_bytes = bytes(instance_aid_value)
    if len(instance_aid_bytes) == 0:
        return
    tar_list_raw = source.get("tarList")
    tar_list: list[bytes] = []
    if isinstance(tar_list_raw, list):
        for tar in tar_list_raw:
            if isinstance(tar, (bytes, bytearray, memoryview)) and len(tar) == 3:
                tar_list.append(bytes(tar))
    minimum_security_level = _coerce_byte(source.get("minimumSecurityLevel"))
    uicc_access_domain = _coerce_octet_string(source.get("uiccAccessDomain"))
    uicc_admin_access_domain = _coerce_octet_string(source.get("uiccAdminAccessDomain"))

    adf_aid_hex = ""
    adf_access_domain = b""
    adf_admin_access_domain = b""
    adf_section = source.get("adfRFMAccess")
    if isinstance(adf_section, dict):
        adf_aid_value = adf_section.get("adfAID")
        if isinstance(adf_aid_value, (bytes, bytearray, memoryview)) and len(adf_aid_value) > 0:
            adf_aid_hex = bytes(adf_aid_value).hex().upper()
        adf_access_domain = _coerce_octet_string(adf_section.get("adfAccessDomain"))
        adf_admin_access_domain = _coerce_octet_string(adf_section.get("adfAdminAccessDomain"))

    image.rfm_instances.append(
        SimProfileRfmInstance(
            instance_aid=instance_aid_bytes.hex().upper(),
            tar_list=tar_list,
            minimum_security_level=minimum_security_level,
            uicc_access_domain=uicc_access_domain,
            uicc_admin_access_domain=uicc_admin_access_domain,
            adf_aid=adf_aid_hex,
            adf_access_domain=adf_access_domain,
            adf_admin_access_domain=adf_admin_access_domain,
        )
    )


_PYSIM_GFM_FILE_TYPE_TO_STRUCTURE: dict[str, str] = {
    "TR": "transparent",
    "LF": "linear-fixed",
    "CY": "cyclic",
    "BT": "ber-tlv",
}


def _consume_generic_file_management(image: SimProfileImage, decoded: dict[str, Any]) -> None:
    """SAIP §5.4 -- materialise a ``genericFileManagement`` PE.

    Routes the PE through pySim's typed ``File`` / GFM
    walker (see ``pysim_gfm_walk``). pySim handles the FCP decode,
    fill-pattern expansion (TS 102 222 §6.3.2.2.2) and content
    accumulation; this consumer maps the resulting ``GfmEntry`` items
    onto ``SimProfileFsNode`` instances with the simulator's
    canonical path/label conventions intact.

    The legacy hand-rolled walker remains as a fallback for inputs
    pySim cannot decode (missing constructs, malformed sequences,
    or pySim-not-installed deploys).
    """
    cmd_list = decoded.get("fileManagementCMD")
    if isinstance(cmd_list, list) is False:
        return

    pysim_entries = pysim_gfm_walk(decoded)
    if pysim_entries:
        _materialize_gfm_via_pysim(image, pysim_entries)
        return

    _consume_generic_file_management_local(image, decoded)


def _materialize_gfm_via_pysim(
    image: SimProfileImage,
    entries: tuple[GfmEntry, ...],
) -> None:
    """Translate pySim-decoded ``GfmEntry`` items into ``SimProfileFsNode``s.

    The translation preserves the simulator's friendly name layer
    (``("MF", "ADF.USIM", "EF.IMSI")``) while delegating descriptor
    parsing and body accumulation to pySim. New DFs/ADFs created by
    the GFM stream are added to ``fid_to_path`` on the fly so any
    downstream EFs anchored under them resolve correctly.
    """
    fid_to_path = _build_fid_to_path_map(image)
    for entry in entries:
        parent_fids = entry.path_fids[:-1] if len(entry.path_fids) > 1 else (0x3F00,)
        df_anchor = _resolve_df_anchor_from_fids(parent_fids, fid_to_path)
        fid_hex = "%04X" % entry.fid
        if entry.file_type in ("MF", "DF", "ADF"):
            aid_hex = entry.df_name.hex().upper()
            df_label = _resolve_df_label_for_fid(fid_hex, aid_hex)
            if fid_hex == "3F00":
                new_path: tuple[str, ...] = ("MF",)
            elif fid_hex.startswith("7F"):
                new_path = ("MF", df_label)
            elif fid_hex.startswith("5F"):
                anchor = df_anchor if len(df_anchor) >= 2 else ("MF",)
                new_path = anchor + (df_label,)
            else:
                new_path = df_anchor + (df_label,)
            kind = "adf" if len(aid_hex) > 0 or entry.file_type == "ADF" else "df"
            image.nodes.append(
                SimProfileFsNode(
                    path=new_path,
                    name=df_label,
                    kind=kind,
                    fid=fid_hex,
                    aid=aid_hex,
                    label=df_label,
                    lifecycle_state=int(entry.lcsi) if entry.lcsi is not None else 0x05,
                )
            )
            fid_to_path[fid_hex] = new_path
            continue
        structure = _PYSIM_GFM_FILE_TYPE_TO_STRUCTURE.get(entry.file_type, "transparent")
        ef_name = _resolve_ef_label(fid_hex)
        ef_path = df_anchor + (ef_name,)
        ef_size = int(entry.file_size or 0)
        record_length = int(entry.rec_len or 0)
        payload = entry.body
        # TS 102 222 §6.3.2.2.2 / TCA §3.5.4: erased flash is 0xFF.
        # pySim's ``file_content_from_tuples`` only fills explicit
        # ranges, so any tail still uncovered after the GFM stream is
        # padded here.
        if ef_size > 0 and len(payload) < ef_size:
            payload = payload + b"\xFF" * (ef_size - len(payload))
        elif ef_size > 0 and len(payload) > ef_size:
            payload = payload[:ef_size]
        records: list[bytes] = []
        data = b""
        if structure in ("linear-fixed", "cyclic") and record_length > 0:
            if len(payload) >= record_length:
                count = len(payload) // record_length
                records = [
                    payload[i * record_length : (i + 1) * record_length]
                    for i in range(count)
                ]
            elif len(payload) > 0:
                records = [payload]
        else:
            data = payload
        # SAIP encodes the SFI byte right-justified per TS 102 221
        # §13.2 (5-bit SFI in the low nibble + 3 reserved zero bits);
        # pySim stores the raw byte verbatim so we mask it to keep
        # the same convention as the local walker.
        sfi_value: int | None = None
        if isinstance(entry.sfi_raw, int):
            sfi_value = int(entry.sfi_raw) & 0x1F
        node = SimProfileFsNode(
            path=ef_path,
            name=ef_name,
            kind="ef",
            fid=fid_hex,
            structure=structure,
            data=data,
            records=records,
            sfi=sfi_value,
            lifecycle_state=int(entry.lcsi) if entry.lcsi is not None else 0x05,
            link_path=entry.link_path,
        )
        image.nodes.append(node)
        fid_to_path[fid_hex] = ef_path


def _resolve_df_anchor_from_fids(
    parent_fids: tuple[int, ...],
    fid_to_path: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    """Resolve a chain of FIDs into a tuple of canonical path labels.

    Walks the chain head-first (MF down to the immediate parent), so a
    GFM ``filePath`` like ``3F00 7F20 5F3A`` resolves to
    ``("MF", "DF.GSM", "DF.PHONEBOOK")`` when those entries already
    exist in ``fid_to_path``. Unknown FIDs resolve to a synthetic
    ``DF.{FID}`` so the result remains stable across passes.
    """
    if not parent_fids:
        return ("MF",)
    path: tuple[str, ...] = ("MF",)
    for fid in parent_fids:
        fid_hex = "%04X" % int(fid)
        if fid_hex == "3F00":
            path = ("MF",)
            continue
        existing = fid_to_path.get(fid_hex)
        if existing is not None:
            path = existing
            continue
        path = path + (_resolve_df_label_for_fid(fid_hex, ""),)
    return path


def _consume_generic_file_management_local(
    image: SimProfileImage, decoded: dict[str, Any]
) -> None:
    """Hand-rolled fallback for ``genericFileManagement``.

    Used when pySim's ``ProfileElementGFM``/``File`` cannot parse the
    incoming PE -- e.g. unconventional fileDescriptor encodings or
    pySim-not-installed deploys. Mirrors the pre-Phase-D behaviour
    exactly so the simulator continues to boot from any historical
    profile fixture.
    """
    cmd_list = decoded.get("fileManagementCMD")
    if isinstance(cmd_list, list) is False:
        return

    fid_to_path = _build_fid_to_path_map(image)
    df_anchor: tuple[str, ...] = ("MF",)
    current_node: SimProfileFsNode | None = None
    current_node_size: int = 0
    current_record_length: int = 0
    cursor: int = 0
    buffer = bytearray()

    def _flush_current() -> None:
        nonlocal current_node, current_node_size, current_record_length, cursor, buffer
        if current_node is None:
            return
        payload = bytes(buffer)
        if current_node_size > 0 and len(payload) < current_node_size:
            payload = payload + b"\xFF" * (current_node_size - len(payload))
        elif current_node_size > 0 and len(payload) > current_node_size:
            payload = payload[:current_node_size]
        if current_node.kind == "ef":
            structure = str(current_node.structure or "transparent")
            if structure in ("linear-fixed", "cyclic") and current_record_length > 0:
                if len(payload) >= current_record_length:
                    count = len(payload) // current_record_length
                    current_node.records = [
                        payload[i * current_record_length : (i + 1) * current_record_length]
                        for i in range(count)
                    ]
                else:
                    current_node.records = [payload] if len(payload) > 0 else []
                current_node.data = b""
            else:
                current_node.data = payload

    for sequence in cmd_list:
        if isinstance(sequence, list) is False:
            continue
        for command in sequence:
            if isinstance(command, tuple) is False or len(command) != 2:
                continue
            tag = str(command[0] or "").strip()
            value = command[1]
            if tag == "filePath":
                _flush_current()
                current_node = None
                current_node_size = 0
                cursor = 0
                buffer = bytearray()
                if isinstance(value, (bytes, bytearray, memoryview)) and len(value) >= 2:
                    fid_bytes = bytes(value)
                    df_anchor = _resolve_df_anchor(fid_bytes, fid_to_path)
                continue
            if tag == "createFCP":
                _flush_current()
                if isinstance(value, dict) is False:
                    current_node = None
                    continue
                fid_bytes = value.get("fileID")
                if isinstance(fid_bytes, (bytes, bytearray, memoryview)) is False:
                    current_node = None
                    continue
                fid_hex = bytes(fid_bytes).hex().upper()
                df_name_value = value.get("dfName")
                lcsi_value = value.get("lcsi")
                lifecycle_state = (
                    int(bytes(lcsi_value)[0])
                    if isinstance(lcsi_value, (bytes, bytearray, memoryview)) and len(lcsi_value) >= 1
                    else 0x05
                )
                file_descriptor_byte = _file_descriptor_first_byte(value)
                # ETSI TS 102 221 §11.1.1.4.3 / TS 102 222 §6.5.6: bits
                # b6..b5 of the file descriptor byte form the file
                # category. ``11`` = DF/ADF, ``00`` = working EF,
                # ``01`` = internal EF. SAIP omits ``dfName`` for plain
                # DFs (e.g. DF.GSM 7F20) so we cannot rely on its
                # presence alone -- fall back to the descriptor bits.
                is_df = isinstance(df_name_value, (bytes, bytearray, memoryview)) and len(df_name_value) > 0
                if is_df is False and (file_descriptor_byte & 0x60) == 0x60:
                    is_df = True
                if is_df:
                    aid_bytes = bytes(df_name_value) if isinstance(df_name_value, (bytes, bytearray, memoryview)) else b""
                    aid_hex = aid_bytes.hex().upper()
                    df_label = _resolve_df_label_for_fid(fid_hex, aid_hex)
                    # ETSI TS 102 221 §13.1 reserves the FID class:
                    #   3F00      MF
                    #   7Fxx      1st-level DF (child of MF)
                    #   5Fxx      2nd-level DF (child of currently
                    #             selected 7Fxx DF)
                    # Honour that ordering so a SAIP issuer that
                    # forgets to insert a ``filePath`` between two
                    # top-level DF declarations still produces a
                    # sane tree.
                    if fid_hex.startswith("7F"):
                        new_parent: tuple[str, ...] = ("MF",)
                    elif fid_hex.startswith("5F"):
                        new_parent = df_anchor if len(df_anchor) >= 2 else ("MF",)
                    else:
                        new_parent = df_anchor
                    new_path = new_parent + (df_label,)
                    image.nodes.append(
                        SimProfileFsNode(
                            path=new_path,
                            name=df_label,
                            kind="adf" if len(aid_hex) > 0 else "df",
                            fid=fid_hex,
                            aid=aid_hex,
                            label=df_label,
                            lifecycle_state=lifecycle_state,
                        )
                    )
                    fid_to_path[fid_hex] = new_path
                    df_anchor = new_path
                    current_node = None
                    current_node_size = 0
                    current_record_length = 0
                    cursor = 0
                    buffer = bytearray()
                    continue
                # EF
                ef_size = _ef_size_from_gfm_descriptor(value)
                file_descriptor_byte = _file_descriptor_first_byte(value)
                structure = _structure_for_descriptor_byte(file_descriptor_byte)
                record_length = _gfm_record_length(value, file_descriptor_byte)
                ef_name = _resolve_ef_label(fid_hex)
                ef_path = df_anchor + (ef_name,)
                sfi_value: int | None = None
                short_efid = value.get("shortEFID")
                if isinstance(short_efid, dict) is False:
                    sfi_value = None
                else:
                    sfi_raw = short_efid.get("shortEFID")
                    if isinstance(sfi_raw, (bytes, bytearray, memoryview)) and len(sfi_raw) >= 1:
                        sfi_value = int(bytes(sfi_raw)[0]) & 0x1F
                node = SimProfileFsNode(
                    path=ef_path,
                    name=ef_name,
                    kind="ef",
                    fid=fid_hex,
                    structure=structure,
                    sfi=sfi_value,
                    lifecycle_state=lifecycle_state,
                    link_path=_decode_fcp_link_path(value),
                )
                image.nodes.append(node)
                fid_to_path[fid_hex] = ef_path
                current_node = node
                current_node_size = ef_size
                current_record_length = record_length
                cursor = 0
                buffer = bytearray()
                continue
            if tag == "fillFileOffset":
                if current_node is None:
                    continue
                try:
                    offset = int(value or 0)
                except (TypeError, ValueError):
                    offset = 0
                cursor += max(0, offset)
                if len(buffer) < cursor:
                    buffer.extend(b"\xFF" * (cursor - len(buffer)))
                continue
            if tag == "fillFileContent":
                if current_node is None:
                    continue
                if isinstance(value, (bytes, bytearray, memoryview)) is False:
                    continue
                payload = bytes(value)
                if len(buffer) < cursor:
                    buffer.extend(b"\xFF" * (cursor - len(buffer)))
                end_offset = cursor + len(payload)
                if len(buffer) < end_offset:
                    buffer.extend(b"\x00" * (end_offset - len(buffer)))
                buffer[cursor:end_offset] = payload
                cursor = end_offset
                continue

    _flush_current()


def _coerce_byte(value: Any) -> int:
    if isinstance(value, (bytes, bytearray, memoryview)) and len(value) >= 1:
        return int(bytes(value)[0]) & 0xFF
    if isinstance(value, int):
        return value & 0xFF
    return 0


# GP Card Spec v2.3.1 §11.1.8 Table 11-16 ``Key Type`` byte encodings.
# Mirrors ``pySim.esim.saip.KeyType`` so the SD-key migration can map
# pySim's resolved enum string back to the on-card byte without
# importing the construct adapter at the use site.
_GP_KEY_TYPE_STRING_TO_BYTE: dict[str, int] = {
    "des-implicit": 0x80,
    "reserved-1": 0x81,
    "tls": 0x81,
    "des-cbc": 0x82,
    "des-ecb": 0x83,
    "tdes-cbc": 0x84,
    "tdes-cbc-2": 0x84,
    "aes": 0x88,
    "hmac-sha1": 0x90,
    "hmac-sha-160": 0x91,
    "rsa-public-e": 0xA0,
    "rsa-public-n": 0xA1,
    "rsa-private-n": 0xA2,
    "rsa-private-d": 0xA3,
    "rsa-crt-p": 0xA4,
    "rsa-crt-q": 0xA5,
    "rsa-crt-pq": 0xA6,
    "rsa-crt-dp1": 0xA7,
    "rsa-crt-dq1": 0xA8,
    "ecc-public-key": 0xB0,
    "ecc-private-key": 0xB1,
    "ecc-field-parameter-a": 0xB2,
    "ecc-field-parameter-b": 0xB3,
    "ecc-field-parameter-g": 0xB4,
    "ecc-field-parameter-n": 0xB5,
    "ecc-field-parameter-k": 0xB6,
    "ecc-key-parameter-reference": 0xF0,
    "extended-format": 0xFF,
}


def _key_type_string_to_byte(key_type: str) -> int:
    """Resolve a pySim ``KeyType`` enum string to its GP byte.

    Returns ``0`` for unknown / empty values so the downstream
    ``SimProfileSecurityDomainKey`` defaults remain stable.
    """
    if not key_type:
        return 0
    key = str(key_type).strip().lower()
    return _GP_KEY_TYPE_STRING_TO_BYTE.get(key, 0)


def _build_fid_to_path_map(image: SimProfileImage) -> dict[str, tuple[str, ...]]:
    """Indexes every materialised node by FID so GFM ``filePath``
    directives can resolve the target parent without walking the tree.

    SAIP §5.4 ``filePath`` carries a 2-byte FID; the simulator uses
    fully-qualified path tuples, so we precompute the mapping at the
    start of each GFM walk. New DFs created by the GFM commands are
    added to this map on the fly.
    """
    mapping: dict[str, tuple[str, ...]] = {}
    for node in image.nodes:
        fid = str(node.fid or "").strip().upper()
        if len(fid) == 0:
            continue
        if fid not in mapping:
            mapping[fid] = node.path
    # Well-known anchors that may not be materialised yet but the GFM
    # stream nevertheless points at (e.g. DF.GSM 7F20 referenced from
    # PE-RFM and PE-GFM in operator BPPs).
    if "3F00" not in mapping:
        mapping["3F00"] = ("MF",)
    if "7F10" not in mapping:
        mapping["7F10"] = ("MF", "DF.TELECOM")
    if "7F20" not in mapping:
        mapping["7F20"] = ("MF", "DF.GSM")
    return mapping


def _resolve_df_anchor(fid_bytes: bytes, fid_to_path: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    fid_hex = fid_bytes.hex().upper()
    if fid_hex == "3F00":
        return ("MF",)
    existing = fid_to_path.get(fid_hex)
    if existing is not None:
        return existing
    # Best-effort fallback: synthesise a stable label and anchor under
    # MF. The GFM `createFCP` that follows will materialise the DF and
    # update the index so subsequent EFs resolve correctly.
    return ("MF", _resolve_df_label_for_fid(fid_hex, ""))


def _resolve_df_label_for_fid(fid_hex: str, aid_hex: str) -> str:
    """Map a DF/ADF FID (and optional AID) to a canonical path label.

    AID-based mapping wins so PKCS#15 / USIM / ISIM / CSIM ADFs land in
    the well-known place even when the issuer reuses non-canonical FIDs.
    Falls back to ETSI TS 31.102 §4.1 / TS 31.103 §4.1 / TS 31.101 §6.4
    fixed FIDs (``7F10`` = DF.TELECOM, ``7F20`` = DF.GSM, ``7F21`` =
    DF.DCS-1800, etc.) before resorting to a deterministic
    ``DF.{FID}`` form so any unknown DF still gets a stable, unique
    component within the image.
    """
    if aid_hex.startswith("A000000063504B43532D3135"):
        return "DF.PKCS-15"
    if aid_hex.startswith("A0000000871002"):
        return "ADF.USIM"
    if aid_hex.startswith("A0000000871004"):
        return "ADF.ISIM"
    if aid_hex.startswith("A0000003431002"):
        return "ADF.CSIM"
    upper = fid_hex.upper()
    well_known = {
        "7F10": "DF.TELECOM",
        "7F20": "DF.GSM",
        "7F21": "DF.DCS-1800",
        "7F22": "DF.IS-41",
        "7F23": "DF.FP-CTS",
        "7F25": "DF.CDMA",
        "7F11": "DF.CD",
        "7F50": "DF.PKCS-15",
        "5F3A": "DF.PHONEBOOK",
        "5F3B": "DF.GSM-ACCESS",
        "5F40": "DF.SOLSA",
        "5F50": "DF.MEXE",
        "5F60": "DF.CCP1",
        "5F70": "DF.SIM-USIM-ACCESS",
        "5FC0": "DF.5GS",
        "5FD0": "DF.SAIP",
        "5FE0": "DF.SNPN",
        "5FF0": "DF.5G_PROSE",
    }
    if upper in well_known:
        return well_known[upper]
    return "DF." + upper


def _resolve_ef_label(fid_hex: str) -> str:
    """Return ``EF.{symbol}`` for FIDs the simulator already recognises,
    else ``EF.{FID}``. The symbol is sourced from ``_FILE_SPECS`` so the
    consumer stays aligned with the rest of the SAIP toolchain.
    """
    upper = fid_hex.upper()
    for spec in _FILE_SPECS.values():
        candidate = str(spec.get("fid", "") or "").upper()
        if candidate == upper:
            return str(spec.get("name", "EF." + upper) or ("EF." + upper))
    return "EF." + upper


def _file_descriptor_first_byte(fcp: dict[str, Any]) -> int:
    raw = fcp.get("fileDescriptor")
    if isinstance(raw, (bytes, bytearray, memoryview)) and len(raw) >= 1:
        return int(bytes(raw)[0]) & 0xFF
    return 0x41


def _structure_for_descriptor_byte(file_descriptor_byte: int) -> str:
    """Decode the ETSI TS 102 221 §11.1.1.4.3 file descriptor byte.

    Bits b3..b1 (low three bits) carry the EF structure:
      000 = no information (treat as transparent)
      001 = transparent EF
      010 = linear-fixed EF
      110 = cyclic EF
    Higher bits encode shareability and file category and are
    inspected separately by the DF/EF discriminator.
    """
    structure_bits = file_descriptor_byte & 0x07
    if structure_bits == 0x02:
        return "linear-fixed"
    if structure_bits == 0x06:
        return "cyclic"
    return "transparent"


def _gfm_record_length(fcp: dict[str, Any], file_descriptor_byte: int) -> int:
    """Pull the record length out of an FCP descriptor.

    SAIP carries the ETSI 5-byte file descriptor TLV verbatim (tag 82,
    length 4 or 5); for record-structured EFs the record length lives
    in bytes 3..4 (big endian). For pure transparent EFs the field is
    irrelevant and reported as 0.
    """
    structure_bits = file_descriptor_byte & 0x07
    if structure_bits not in (0x02, 0x06):
        return 0
    raw = fcp.get("fileDescriptor")
    if isinstance(raw, (bytes, bytearray, memoryview)) is False:
        return 0
    body = bytes(raw)
    if len(body) >= 4:
        return int.from_bytes(body[2:4], "big", signed=False)
    return 0


def _ef_size_from_gfm_descriptor(fcp: dict[str, Any]) -> int:
    raw = fcp.get("efFileSize")
    if isinstance(raw, (bytes, bytearray, memoryview)) is False:
        return 0
    body = bytes(raw)
    if len(body) == 0:
        return 0
    return int.from_bytes(body, "big", signed=False)


def _consume_aka_parameter(image: SimProfileImage, decoded: dict[str, Any]) -> None:
    """SAIP §5.8 -- materialise an ``akaParameter`` PE.

    Routes the decoded dict through pySim's ``ProfileElementAKA``
    wrapper. The wrapper's ``_post_decode`` runs
    ``_fixup_sqnInit_dec``, which substitutes the asn1tools default
    placeholder ``'0x000000000000'`` with a 32-element list of 6-byte
    zeros (TS 33.102 §6.3.7 / 3GPP TS 35.205 Annex E SQN init layout).
    """
    source = pysim_normalize_aka_decoded(decoded)
    if isinstance(source, dict) is False:
        source = decoded
    algo_configuration = source.get("algoConfiguration")
    if isinstance(algo_configuration, tuple) is False or len(algo_configuration) != 2:
        return
    choice_name = str(algo_configuration[0] or "").strip()
    choice_value = algo_configuration[1]
    if choice_name != "algoParameter":
        # mappingParameter redirects Ki/OPc to another application. Skip silently
        # until the simulator grows cross-application Ki sharing.
        return
    if isinstance(choice_value, dict) is False:
        return

    algorithm = _saip_algorithm_name(choice_value.get("algorithmID"))
    if len(algorithm) == 0:
        return
    ki_bytes = _coerce_octet_string(choice_value.get("key"))
    opc_bytes = _coerce_octet_string(choice_value.get("opc"))
    if len(ki_bytes) == 0:
        return
    if _aka_key_length_is_valid(algorithm, len(ki_bytes)) is False:
        return
    if len(opc_bytes) > 0 and _aka_opc_length_is_valid(algorithm, len(opc_bytes)) is False:
        opc_bytes = b""

    config = SimProfileAuthConfig(algorithm=algorithm)
    config.ki = ki_bytes
    if len(opc_bytes) > 0:
        config.opc = opc_bytes

    auth_counter_max = _coerce_octet_string(choice_value.get("authCounterMax"))
    if len(auth_counter_max) > 0:
        config.auth_counter_max = auth_counter_max

    number_of_keccak = choice_value.get("numberOfKeccak")
    try:
        keccak_value = int(number_of_keccak) if number_of_keccak is not None else 1
    except (TypeError, ValueError):
        keccak_value = 1
    # TS 35.231 Annex A: numberOfKeccak iterations are bounded to [1, 255].
    keccak_value = max(1, min(0xFF, keccak_value))
    config.number_of_keccak = keccak_value

    sqn_init = source.get("sqnInit")
    if isinstance(sqn_init, list) and len(sqn_init) > 0:
        candidate = _coerce_octet_string(sqn_init[0])
        if len(candidate) == 6:
            config.sqn = candidate

    image.auth_config = config


def _aka_key_length_is_valid(algorithm: str, key_length: int) -> bool:
    normalized = algorithm.strip().lower()
    if normalized == "tuak":
        return key_length in (16, 32)
    if normalized in ("milenage", "usim-test-algorithm"):
        return key_length == 16
    return key_length > 0


def _aka_opc_length_is_valid(algorithm: str, opc_length: int) -> bool:
    normalized = algorithm.strip().lower()
    if normalized == "tuak":
        return opc_length == 32
    if normalized == "milenage":
        return opc_length == 16
    return opc_length in (16, 32)


def _coerce_octet_string(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return b""
    return b""


def _saip_algorithm_name(algorithm_id: Any) -> str:
    try:
        raw_value = int(algorithm_id)
    except (TypeError, ValueError):
        text = str(algorithm_id or "").strip().lower()
        if text in ("milenage", "tuak", "usim-test-algorithm"):
            return text
        return ""
    if raw_value == 1:
        return "milenage"
    if raw_value == 2:
        return "tuak"
    if raw_value == 3:
        return "usim-test-algorithm"
    return ""


def _materialize_file_payload(value: Any) -> bytes | None:
    materialised = _materialize_ef_value(value)
    if materialised is None:
        return None
    payload, _ = materialised
    return payload


def _materialize_ef_value(value: Any) -> tuple[bytes, dict[str, Any]] | None:
    """Extract the EF payload and its associated ``fileDescriptor`` dict.

    SAIP §5.1 stores EF contents as a ``CHOICE`` SEQUENCE that interleaves
    a ``fileDescriptor`` element with one or more ``fillFileContent`` /
    ``fillFileOffset`` directives. The directives describe a contiguous
    image of the file written from offset 0; ``fillFileOffset`` jumps the
    write cursor forward by N bytes, leaving the gap padded with 0xFF
    (TCA Profile Interoperability §3.5.4 -- erased flash state).
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), {}
    if isinstance(value, list) is False:
        return b"", {}

    descriptor: dict[str, Any] = {}
    chunks: list[tuple[int, bytes]] = []
    cursor = 0
    for item in value:
        if isinstance(item, tuple) is False or len(item) != 2:
            continue
        tag_name = str(item[0] or "").strip()
        if tag_name == "doNotCreate":
            return None
        if tag_name == "fileDescriptor" and isinstance(item[1], dict):
            descriptor = item[1]
            continue
        if tag_name == "fillFileOffset":
            try:
                cursor += int(item[1] or 0)
            except Exception:
                pass
            continue
        if tag_name == "fillFileContent":
            payload = item[1]
            if isinstance(payload, (bytes, bytearray, memoryview)):
                data = bytes(payload)
                if len(data) > 0:
                    chunks.append((cursor, data))
                    cursor += len(data)

    total_length = max((offset + len(blob) for offset, blob in chunks), default=0)
    if total_length == 0:
        return b"", descriptor
    buffer = bytearray(b"\xFF" * total_length)
    for offset, blob in chunks:
        buffer[offset : offset + len(blob)] = blob
    return bytes(buffer), descriptor


def _finalize_image(image: SimProfileImage) -> SimProfileImage | None:
    deduped: dict[tuple[str, ...], SimProfileFsNode] = {}
    for node in image.nodes:
        if len(node.path) == 0:
            continue
        existing = deduped.get(node.path)
        if existing is None:
            deduped[node.path] = node
            continue
        replacement_has_payload = len(node.data) > 0 or len(node.records) > 0 or len(node.aid) > 0
        existing_has_payload = (
            len(existing.data) > 0 or len(existing.records) > 0 or len(existing.aid) > 0
        )
        if replacement_has_payload or existing_has_payload is False:
            deduped[node.path] = node
    image.nodes = sorted(deduped.values(), key=lambda item: (len(item.path), item.path))

    if len(image.profile_name) == 0 and len(image.iccid) > 0:
        image.profile_name = f"ICCID-{image.iccid[-4:]}"

    usim_imsi = _node_by_path(image, ("MF", "ADF.USIM", "EF.IMSI"))
    if usim_imsi is not None and len(usim_imsi.data) > 0:
        decoded = decode_imsi_ef(usim_imsi.data)
        if len(decoded) > 0:
            image.imsi = decoded
    isim_impi = _node_by_path(image, ("MF", "ADF.ISIM", "EF.IMPI"))
    if isim_impi is not None and len(isim_impi.data) > 0:
        try:
            image.impi = isim_impi.data.decode("utf-8", "ignore").strip()
        except Exception:
            pass

    if len(image.iccid) > 0 and _node_by_path(image, ("MF", "EF.ICCID")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "EF.ICCID"),
                name="EF.ICCID",
                kind="ef",
                fid="2FE2",
                structure="transparent",
                data=encode_iccid_ef(image.iccid),
                sfi=0x02,
            )
        )

    if len(image.imsi) > 0 and _node_by_path(image, ("MF", "ADF.USIM")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.USIM"),
                name="ADF.USIM",
                kind="adf",
                fid="7FF0",
                aid=USIM_AID,
                label="USIM",
            )
        )
    if len(image.imsi) > 0 and _node_by_path(image, ("MF", "ADF.USIM", "EF.IMSI")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.USIM", "EF.IMSI"),
                name="EF.IMSI",
                kind="ef",
                fid="6F07",
                structure="transparent",
                data=encode_imsi_ef(image.imsi),
                sfi=0x07,
            )
        )
    if len(image.imsi) > 0 and _node_by_path(image, ("MF", "ADF.USIM", "EF.AD")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.USIM", "EF.AD"),
                name="EF.AD",
                kind="ef",
                fid="6FAD",
                structure="transparent",
                data=bytes.fromhex("00000002"),
            )
        )

    if len(image.impi) > 0 and _node_by_path(image, ("MF", "ADF.ISIM")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.ISIM"),
                name="ADF.ISIM",
                kind="adf",
                fid="7FF2",
                aid=ISIM_AID,
                label="ISIM",
            )
        )
    if len(image.impi) > 0 and _node_by_path(image, ("MF", "ADF.ISIM", "EF.IMPI")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.ISIM", "EF.IMPI"),
                name="EF.IMPI",
                kind="ef",
                fid="6F02",
                structure="transparent",
                data=image.impi.encode("utf-8"),
            )
        )

    image.nodes = sorted({node.path: node for node in image.nodes}.values(), key=lambda item: (len(item.path), item.path))
    if len(image.nodes) == 0 and len(image.iccid) == 0 and len(image.imsi) == 0 and len(image.impi) == 0:
        return None
    return image


def _node_by_path(image: SimProfileImage, path: tuple[str, ...]) -> SimProfileFsNode | None:
    for node in image.nodes:
        if node.path == path:
            return node
    return None
