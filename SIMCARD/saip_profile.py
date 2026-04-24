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
from SIMCARD.state import SimProfileAuthConfig, SimProfileFsNode, SimProfileImage
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
    },
    "cd": {
        "base_path": ("MF", "DF.CD"),
        "root_path": ("MF", "DF.CD"),
        "root_kind": "df",
        "root_fid": "7F11",
        "root_aid": "",
        "root_label": "",
    },
    "telecom": {
        "base_path": ("MF", "DF.TELECOM"),
        "root_path": ("MF", "DF.TELECOM"),
        "root_kind": "df",
        "root_fid": "7F10",
        "root_aid": "",
        "root_label": "",
    },
    "phonebook": {
        "base_path": ("MF", "DF.TELECOM", "DF.PHONEBOOK"),
        "root_path": ("MF", "DF.TELECOM", "DF.PHONEBOOK"),
        "root_kind": "df",
        "root_fid": "5F3A",
        "root_aid": "",
        "root_label": "",
    },
    "gsm-access": {
        "base_path": ("MF", "ADF.USIM", "DF.GSM-ACCESS"),
        "root_path": ("MF", "ADF.USIM", "DF.GSM-ACCESS"),
        "root_kind": "df",
        "root_fid": "5F3B",
        "root_aid": "",
        "root_label": "",
    },
    "usim": {
        "base_path": ("MF", "ADF.USIM"),
        "root_path": ("MF", "ADF.USIM"),
        "root_kind": "adf",
        "root_fid": "7FF0",
        "root_aid": USIM_AID,
        "root_label": "USIM",
    },
    "opt-usim": {
        "base_path": ("MF", "ADF.USIM"),
        "root_path": ("MF", "ADF.USIM"),
        "root_kind": "adf",
        "root_fid": "7FF0",
        "root_aid": USIM_AID,
        "root_label": "USIM",
    },
    "isim": {
        "base_path": ("MF", "ADF.ISIM"),
        "root_path": ("MF", "ADF.ISIM"),
        "root_kind": "adf",
        "root_fid": "7FF2",
        "root_aid": ISIM_AID,
        "root_label": "ISIM",
    },
    "opt-isim": {
        "base_path": ("MF", "ADF.ISIM"),
        "root_path": ("MF", "ADF.ISIM"),
        "root_kind": "adf",
        "root_fid": "7FF2",
        "root_aid": ISIM_AID,
        "root_label": "ISIM",
    },
    "csim": {
        "base_path": ("MF", "ADF.CSIM"),
        "root_path": ("MF", "ADF.CSIM"),
        "root_kind": "adf",
        "root_fid": "7FF3",
        "root_aid": "",
        "root_label": "CSIM",
    },
    "opt-csim": {
        "base_path": ("MF", "ADF.CSIM"),
        "root_path": ("MF", "ADF.CSIM"),
        "root_kind": "adf",
        "root_fid": "7FF3",
        "root_aid": "",
        "root_label": "CSIM",
    },
    "eap": {
        "base_path": ("MF", "DF.EAP"),
        "root_path": ("MF", "DF.EAP"),
        "root_kind": "df",
        "root_fid": "7F20",
        "root_aid": "",
        "root_label": "",
    },
    "df-5gs": {
        "base_path": ("MF", "ADF.USIM", "DF.5GS"),
        "root_path": ("MF", "ADF.USIM", "DF.5GS"),
        "root_kind": "df",
        "root_fid": "5FC0",
        "root_aid": "",
        "root_label": "",
    },
    "df-saip": {
        "base_path": ("MF", "ADF.USIM", "DF.SAIP"),
        "root_path": ("MF", "ADF.USIM", "DF.SAIP"),
        "root_kind": "df",
        "root_fid": "5FD0",
        "root_aid": "",
        "root_label": "",
    },
    "df-snpn": {
        "base_path": ("MF", "ADF.USIM", "DF.SNPN"),
        "root_path": ("MF", "ADF.USIM", "DF.SNPN"),
        "root_kind": "df",
        "root_fid": "5FE0",
        "root_aid": "",
        "root_label": "",
    },
    "df-5gprose": {
        "base_path": ("MF", "ADF.USIM", "DF.5G_PROSE"),
        "root_path": ("MF", "ADF.USIM", "DF.5G_PROSE"),
        "root_kind": "df",
        "root_fid": "5FF0",
        "root_aid": "",
        "root_label": "",
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


def decode_profile_image(
    upp_bytes: bytes,
    *,
    default_iccid: str = "",
    default_name: str = "",
    default_imsi: str = "",
    default_impi: str = "",
) -> SimProfileImage | None:
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
        return

    if pe_type == "akaParameter":
        _consume_aka_parameter(image, decoded)
        return

    spec = _SECTION_SPECS.get(pe_type)
    if spec is None:
        return

    root_path = spec.get("root_path")
    if isinstance(root_path, tuple):
        image.nodes.append(
            SimProfileFsNode(
                path=root_path,
                name=root_path[-1],
                kind=str(spec.get("root_kind", "df") or "df"),
                fid=str(spec.get("root_fid", "") or ""),
                aid=str(spec.get("root_aid", "") or ""),
                label=str(spec.get("root_label", "") or ""),
            )
        )

    base_path = tuple(spec.get("base_path", ("MF",)))
    for key, value in decoded.items():
        if key.endswith("-header") or key == "templateID":
            continue
        file_spec = _FILE_SPECS.get(str(key))
        if file_spec is None:
            continue
        payload = _materialize_file_payload(value)
        if payload is None:
            continue
        structure = str(file_spec.get("structure", "transparent") or "transparent")
        records = [payload] if structure == "linear-fixed" and len(payload) > 0 else []
        data = b"" if structure == "linear-fixed" else payload
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
            )
        )


def _consume_aka_parameter(image: SimProfileImage, decoded: dict[str, Any]) -> None:
    algo_configuration = decoded.get("algoConfiguration")
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

    sqn_init = decoded.get("sqnInit")
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
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, list) is False:
        return b""
    stream = io.BytesIO()
    for item in value:
        if isinstance(item, tuple) is False or len(item) != 2:
            continue
        tag_name = str(item[0] or "").strip()
        if tag_name == "doNotCreate":
            return None
        if tag_name == "fillFileOffset":
            try:
                stream.seek(int(item[1] or 0), io.SEEK_CUR)
            except Exception:
                continue
            continue
        if tag_name == "fillFileContent":
            payload = item[1]
            if isinstance(payload, (bytes, bytearray, memoryview)):
                stream.write(bytes(payload))
    return stream.getvalue()


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
