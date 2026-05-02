from __future__ import annotations

import copy

from SIMCARD.state import (
    DEFAULT_SIM_ATR,
    SimCardState,
    SimChvReference,
    SimEimEntry,
    SimEuiccConfiguredData,
    SimFileNode,
    SimGpAppEntry,
    SimProfileAuthConfig,
    SimProfileEntry,
    SimProfileFsNode,
    SimProfileImage,
    SimProfilePinEntry,
    SimProfilePukEntry,
    SimProfileRfmInstance,
    SimProfileSecurityDomain,
)
from SIMCARD.utils import encode_iccid_ef, encode_imsi_ef, tlv


USIM_AID = "A0000000871002FF86FF112233445566"
ISIM_AID = "A0000000871004FF86FF112233445566"
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
ECASD_AID = "A0000005591010FFFFFFFF8900000200"
ISDP1_AID = "A0000005591010FFFFFFFF8900001100"
ISDP2_AID = "A0000005591010FFFFFFFF8900001200"
MNO_SD_AID = "A000000151000000"
PROFILE_AID_PREFIX = "A0000005591010FFFFFFFF890000"
PROFILE_AID_SUFFIX_START = 0x1100
PROFILE_AID_SUFFIX_STEP = 0x0100
PROFILE_AID_SUFFIX_MAX = 0xFF00


def next_generated_profile_aid(profiles: list[SimProfileEntry]) -> str:
    """Allocate the next ISD-P AID following the GSMA SGP.02/22 convention.

    Profile AIDs use the prefix ``A0000005591010FFFFFFFF890000`` and a 16-bit
    suffix where the third nibble from the right identifies the profile slot
    (0x1100, 0x1200, 0x1300, ...). The last byte stays at 0x00 so every
    generated ISD-P lands on a clean slot boundary.
    """
    used = {str(profile.aid or "").strip().upper() for profile in profiles}
    suffix = PROFILE_AID_SUFFIX_START
    while suffix <= PROFILE_AID_SUFFIX_MAX:
        candidate = f"{PROFILE_AID_PREFIX}{suffix:04X}"
        if candidate not in used:
            return candidate
        suffix += PROFILE_AID_SUFFIX_STEP
    raise RuntimeError("Exhausted available ISD-P AID slots (0x1100..0xFF00 step 0x0100)")


def _app_record(aid_hex: str, label: str) -> bytes:
    value = tlv("4F", bytes.fromhex(aid_hex)) + tlv("50", label.encode("utf-8"))
    return tlv("61", value)


def _profile_path_node_id(path: tuple[str, ...]) -> str:
    if len(path) == 1 and path[0] == "MF":
        return "3F00"
    sanitized = [part.replace("/", "_").replace(" ", "_") for part in path[1:]]
    return "PROFILE::" + "::".join(sanitized)


def _encode_plmn_3gpp(mcc: str, mnc: str) -> bytes:
    mcc_digits = str(mcc or "").strip()
    mnc_digits = str(mnc or "").strip()
    if len(mcc_digits) != 3 or mcc_digits.isdigit() is False:
        return b"\xFF\xFF\xFF"
    if len(mnc_digits) not in (2, 3) or mnc_digits.isdigit() is False:
        return b"\xFF\xFF\xFF"
    mcc_values = [int(digit) for digit in mcc_digits]
    mnc_values = [int(digit) for digit in mnc_digits]
    if len(mnc_values) == 2:
        mnc3 = 0xF
    else:
        mnc3 = mnc_values[2]
    byte1 = ((mcc_values[1] & 0x0F) << 4) | (mcc_values[0] & 0x0F)
    byte2 = ((mnc3 & 0x0F) << 4) | (mcc_values[2] & 0x0F)
    byte3 = ((mnc_values[1] & 0x0F) << 4) | (mnc_values[0] & 0x0F)
    return bytes((byte1, byte2, byte3))


def _mcc_mnc_from_imsi(imsi: str, mnc_length: int) -> tuple[str, str]:
    digits = str(imsi or "").strip()
    if len(digits) < 5 or digits.isdigit() is False:
        return "", ""
    if mnc_length not in (2, 3):
        mnc_length = 2
    mcc_text = digits[:3]
    mnc_text = digits[3 : 3 + mnc_length]
    return mcc_text, mnc_text


def _encode_ef_ust_default() -> bytes:
    # USIM Service Table per TS 31.102 §4.2.8. Bit numbering inside
    # each byte starts at LSB. We enable a baseline that lets a 4G/5G
    # modem complete attach against the simulator and also advertises
    # the voice / SMS services whose EFs are seeded under ADF.USIM:
    #
    #   4 SDN (Service Dialling Numbers),
    #   8 OCI/OCT (Outgoing Call Information / Timer),
    #   9 ICI/ICT (Incoming Call Information / Timer),
    #  10 SMS message storage,
    #  11 SMS Status Reports,
    #  12 SMS Parameters (already seeded as EF.SMSP),
    #  19 SPN, 21 MSISDN, 27 GSM access,
    #  30 Call Control by USIM (D4 envelope decoder),
    #  31 MO-SMS Control by USIM (D5 envelope decoder),
    #  33 RFU/must-be-1, 38 GSM security context,
    #  45 PLMN Network Name (PNN),
    #  46 Operator PLMN List (OPL),
    #  49 Call Forwarding Indication Status (CFIS),
    #  51 Service Provider Display Information (SPDI),
    #  55 Last Number Dialled,
    #  71 Equivalent HPLMN (EHPLMN list),
    #  91 Support for SM-over-IP (PSISMSC),
    #  122 Subscription identifier de-concealing function (5G SUCI by ME),
    #  124 Subscription identifier de-concealing function support (5G),
    #  125 SUCI calculation by the USIM (TS 31.102 §5.1.1.5),
    #  126 EAP-AKA' authentication context support (TS 33.402 / TS 33.501),
    #  129 5GS Mobility Management,
    #  130 5GS Session Management.
    #
    # Enabling service 125 advertises that the USIM (i.e. this
    # simulator) is willing to compute the SUCI itself, which matches
    # our GET IDENTITY (CLA=80 INS=78) implementation. Enabling
    # services 30/31 tells the modem that the USIM accepts D4 / D5
    # envelopes, which now genuinely decode their payloads.
    service_bytes = bytearray(17)
    enabled_services = (
        4, 8, 9, 10, 11, 12, 19, 21, 27, 30, 31, 33, 38,
        45, 46, 49, 51, 55, 71, 91,
        122, 124, 125, 126, 129, 130,
    )
    for service_number in enabled_services:
        byte_index = (service_number - 1) // 8
        bit_index = (service_number - 1) % 8
        if byte_index >= len(service_bytes):
            service_bytes.extend(b"\x00" * (byte_index + 1 - len(service_bytes)))
        service_bytes[byte_index] |= 1 << bit_index
    return bytes(service_bytes)


def _encode_ef_spn(service_provider: str) -> bytes:
    name_bytes = str(service_provider or "YggdraSIM").encode("utf-8")[:16]
    padding = b"\xFF" * (16 - len(name_bytes))
    return bytes((0x01,)) + name_bytes + padding


def _encode_ef_loci(plmn_bytes: bytes) -> bytes:
    tmsi = b"\xFF\xFF\xFF\xFF"
    lac = b"\xFF\xFE"
    tmsi_time = b"\xFF"
    status = b"\x01"
    return tmsi + bytes(plmn_bytes) + lac + tmsi_time + status


def _encode_ef_psloci(plmn_bytes: bytes) -> bytes:
    ptmsi = b"\xFF\xFF\xFF\xFF"
    ptmsi_sig = b"\xFF\xFF\xFF"
    lac = b"\xFF\xFE"
    rac = b"\xFF"
    status = b"\x01"
    return ptmsi + ptmsi_sig + bytes(plmn_bytes) + lac + rac + status


def _encode_ef_epsloci(plmn_bytes: bytes) -> bytes:
    guti = bytes(plmn_bytes) + b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    tai = bytes(plmn_bytes) + b"\xFF\xFE"
    status = b"\x01"
    return guti + tai + status


def _encode_ef_hplmnwact(plmn_bytes: bytes) -> bytes:
    access_technology = b"\x80\x80"
    return bytes(plmn_bytes) + access_technology


def _encode_ef_smsp_record(*, alpha_length: int = 12) -> bytes:
    # 3GPP TS 31.102 §4.2.27 EF.SMSP. Layout per §4.4.4:
    #   Y  bytes  Alpha Identifier (Y = profile-defined; 12 is typical)
    #   1  byte   Parameter Indicators (bit=1 means "absent"; 0xFF = no params)
    #  12  bytes  TP-Destination Address (length + TON/NPI + 10 BCD)
    #  12  bytes  TS-Service Centre Address (same shape as above)
    #   1  byte   TP-Protocol Identifier
    #   1  byte   TP-Data Coding Scheme
    #   1  byte   TP-Validity Period
    # An attach-ready default leaves every field "not provisioned"
    # (0xFF) so the modem treats the record as a writable slot rather
    # than an active SC profile. This matches what blank UICCs ship.
    alpha = b"\xFF" * max(0, int(alpha_length))
    parameter_indicators = b"\xFF"
    tp_destination_address = b"\xFF" * 12
    ts_service_centre_address = b"\xFF" * 12
    tp_pid = b"\xFF"
    tp_dcs = b"\xFF"
    tp_validity = b"\xFF"
    return (
        alpha
        + parameter_indicators
        + tp_destination_address
        + ts_service_centre_address
        + tp_pid
        + tp_dcs
        + tp_validity
    )


def _encode_ef_smss_default() -> bytes:
    # 3GPP TS 31.102 §4.2.9 EF.SMSS. Two octets:
    #   Byte 0  Last Used TP-MR (0x00 on a freshly issued card).
    #   Byte 1  SMS Memory Capacity Exceeded Notification Flag
    #           (0xFF = no notification required, the MS has free
    #            slots; 0x00 = notification owed to the SC).
    return bytes((0x00, 0xFF))


def _encode_ef_msisdn_record(*, alpha_length: int = 8) -> bytes:
    # 3GPP TS 31.102 §4.2.40 EF.MSISDN. Each record:
    #   Y  bytes  Alpha Identifier (Y = profile-defined; 8 default)
    #   1  byte   Length of BCD number/SSC + TON/NPI (combined)
    #   1  byte   TON / NPI
    #  10  bytes  BCD-encoded dialling number / SSC string
    #   1  byte   Capability/Configuration 1 record identifier
    #   1  byte   Extension5 record identifier
    # A blank slot is all 0xFF; modems UPDATE RECORD into it once
    # the operator provisions an MSISDN OTA. The fixed record size
    # is therefore Y + 14 (8 + 14 = 22 by default).
    alpha = b"\xFF" * max(0, int(alpha_length))
    body = b"\xFF" * 14
    return alpha + body


def _encode_ef_mbdn_record(*, alpha_length: int = 8) -> bytes:
    # 3GPP TS 31.102 §4.2.56 EF.MBDN. Same record layout as
    # EF.MSISDN: alpha + 14-byte dial body. Defaults all-FF so the
    # MS treats the entry as "no mailbox dialing number".
    alpha = b"\xFF" * max(0, int(alpha_length))
    body = b"\xFF" * 14
    return alpha + body


def _encode_ef_mbi_record() -> bytes:
    # 3GPP TS 31.102 §4.2.55 EF.MBI. Each record carries 4 indices
    # into EF.MBDN keyed by mailbox type:
    #   Byte 0 Voicemail
    #   Byte 1 Fax
    #   Byte 2 Electronic Mail
    #   Byte 3 Other
    # 0x00 means "no record" -> the simulator advertises voicemail
    # pointing at EF.MBDN record #1 and the rest disabled, matching
    # the most common provisioning.
    return bytes((0x01, 0x00, 0x00, 0x00))


def _encode_ef_mwis_record() -> bytes:
    # 3GPP TS 31.102 §4.2.57 EF.MWIS. Each record:
    #   Byte 0 Indicator status (bitmap; bits 1..4 enable/disable
    #          voicemail/fax/email/other "message waiting").
    #   Byte 1 Voicemail message count.
    #   Byte 2 Fax message count.
    #   Byte 3 Email message count.
    #   Byte 4 Other message count.
    # Default state = no flags set, no messages waiting.
    return bytes((0x00, 0x00, 0x00, 0x00, 0x00))


def _encode_ef_lnd_record(*, alpha_length: int = 8) -> bytes:
    # 3GPP TS 31.102 §4.2.32 EF.LND (Last Number Dialled). Same
    # record shape as EF.MSISDN: alpha + 14-byte dial body. The
    # cyclic-EF semantics mean the most-recent record at the
    # head; UPDATE RECORD with mode 0x03 (previous) overwrites the
    # oldest slot. A freshly issued card ships one all-FF record
    # so READ RECORD against the empty slot doesn't return 6A 83.
    alpha = b"\xFF" * max(0, int(alpha_length))
    body = b"\xFF" * 14
    return alpha + body


def _encode_ef_ici_record(*, alpha_length: int = 8) -> bytes:
    # 3GPP TS 31.102 §4.2.20 EF.ICI - Incoming Call Information.
    # Per Table 4.2.20.1, each cyclic record carries:
    #   Y bytes Alpha Identifier
    #   1 byte  Length of BCD number/SSC (X)
    #   1 byte  TON / NPI
    #  10 bytes BCD-encoded number / SSC
    #   1 byte  CCP record id
    #   1 byte  Ext5 record id
    #   3 bytes Date and time (BCD: yymmdd hhmmss truncated)
    #   2 bytes Duration (in seconds, BE)
    #   1 byte  Status byte (bit 0 = unread, bit 1 = link valid)
    #   1 byte  Link to phonebook reference EF
    #   2 bytes Phonebook record number
    # Default record length = Y + 22 (8 + 22 = 30 bytes) all-FF
    # so the modem reads "no incoming calls yet".
    alpha = b"\xFF" * max(0, int(alpha_length))
    body = b"\xFF" * 22
    return alpha + body


def _encode_ef_oci_record(*, alpha_length: int = 8) -> bytes:
    # 3GPP TS 31.102 §4.2.21 EF.OCI - Outgoing Call Information.
    # Same record shape as EF.ICI minus the unread/link status
    # byte (outgoing calls have no read/unread concept). The
    # simulator encodes the conservative full-Y+22 layout because
    # modems negotiate the per-record length via the FCP at
    # SELECT time and trim trailing bytes anyway.
    alpha = b"\xFF" * max(0, int(alpha_length))
    body = b"\xFF" * 22
    return alpha + body


def _encode_ef_ict_record() -> bytes:
    # 3GPP TS 31.102 §4.2.22 EF.ICT - Incoming Call Timer. Each
    # cyclic record holds a 3-byte cumulative timer (units of
    # 1 second, BE). Fresh card ships zeros so the modem reads
    # "no accumulated incoming time" and starts adding from 0.
    return bytes((0x00, 0x00, 0x00))


def _encode_ef_oct_record() -> bytes:
    # 3GPP TS 31.102 §4.2.23 EF.OCT - Outgoing Call Timer. Same
    # 3-byte cumulative-seconds shape as EF.ICT.
    return bytes((0x00, 0x00, 0x00))


def _encode_ef_sms_record() -> bytes:
    # 3GPP TS 31.102 §4.2.25 EF.SMS - SMS message storage. Each
    # linear-fixed record is 176 bytes:
    #   Byte 0       Status (b1=used, b2=read, b3=stored sent ok)
    #   Bytes 1..175 TPDU (TS 23.040 SMS-DELIVER / SMS-SUBMIT)
    # A fresh card ships every slot with status 0x00 ("free,
    # space available") and the TPDU body padded with 0xFF so a
    # store-SMS command writes over the placeholder cleanly.
    return bytes((0x00,)) + b"\xFF" * 175


def _encode_ef_smsr_record() -> bytes:
    # 3GPP TS 31.102 §4.2.28 EF.SMSR - SMS Status Reports. Each
    # linear-fixed record is 30 bytes:
    #   Byte 0       Link to EF.SMS record (1..n) or 0x00 if unused.
    #   Bytes 1..29  Status Report TPDU (TS 23.040 §9.2.2.3 -- up to
    #                29 octets after stripping the SMSC address).
    # Default: empty slot (0x00 link, FF padding) so the modem treats
    # the record as available and writes a real status report into it
    # via UPDATE RECORD once the SMSC delivers one.
    return bytes((0x00,)) + b"\xFF" * 29


def _encode_ef_sdn_record(*, alpha_length: int = 8) -> bytes:
    # 3GPP TS 31.102 §4.2.46 EF.SDN - Service Dialling Numbers.
    # Same record shape as EF.MSISDN: alpha + 14-byte dial body.
    # Default seed: one all-FF slot. Operators provision SDN
    # records OTA (e.g. customer service shortcut, voicemail
    # operator code) via UPDATE RECORD once provisioning runs.
    alpha = b"\xFF" * max(0, int(alpha_length))
    body = b"\xFF" * 14
    return alpha + body


def _encode_ef_ehplmnpi_default() -> bytes:
    # 3GPP TS 31.102 §4.2.84 EF.EHPLMNPI - Equivalent HPLMN
    # Presentation Indication. Single transparent byte:
    #   bit 1 set   = display all EHPLMNs.
    #   bit 1 cleared = display HPLMN only (default behaviour).
    #   bits 2..8 RFU (must be 0).
    # The default seed leaves all bits cleared so the modem
    # falls back to displaying the HPLMN, matching what most
    # operators ship.
    return bytes((0x00,))


def _encode_ef_spdi_default() -> bytes:
    # 3GPP TS 31.102 §4.2.66 EF.SPDI - Service Provider
    # Display Information. Transparent EF carrying a single
    # outer TLV ``A3 LL`` whose value is a list of nested
    # PLMN entries inside an inner ``80 LL`` envelope:
    #
    #   A3 LL                       SPDI list
    #     80 NN                     PLMN list
    #       <PLMN1> <PLMN2> ...     each PLMN = 3 bytes BCD
    #
    # On a freshly issued card the operator has not yet
    # populated the SPDI list, so the EF advertises an empty
    # PLMN list (`A3 02 80 00`). UPDATE BINARY by the issuer
    # OTA replaces this scaffold with real PLMN entries.
    return bytes((0xA3, 0x02, 0x80, 0x00))


def _encode_ef_psismsc_record(
    uri: str = "sip:smsc@ims.mnc001.mcc001.3gppnetwork.org",
    *,
    record_length: int = 64,
) -> bytes:
    # 3GPP TS 31.102 §4.2.81 EF.PSISMSC - Public Service
    # Identity of SM-SC. Linear-fixed EF whose records carry
    # the SIP URI of the operator's SM-SC for SM-over-IP
    # messaging discovery (TS 23.204).
    #
    # Each record is laid out as ``80 LL <type><uri>``:
    #
    #   Tag    0x80 (Public Service Identity TLV).
    #   Length total bytes that follow.
    #   Type   one byte; ``0x00`` flags the value as a SIP /
    #          TEL URI (matches the encoding used by EF.PCSCF).
    #   URI    UTF-8 bytes of the URI, no terminator.
    #
    # Records are FF-padded to a fixed width so READ RECORD
    # returns a deterministic length regardless of the actual
    # URI size. The default seed targets the TS 23.003-shaped
    # IMS realm derived from the simulator's reserved test
    # PLMN (MCC 001 / MNC 01). Operators OTA-overwrite via
    # UPDATE RECORD once provisioning runs.
    payload = b"\x00" + str(uri or "").strip().encode("utf-8", "ignore")
    if len(payload) > 0xFE:
        payload = payload[:0xFE]
    tlv_blob = bytes((0x80, len(payload))) + payload
    if len(tlv_blob) >= record_length:
        return tlv_blob[:record_length]
    return tlv_blob + b"\xFF" * (record_length - len(tlv_blob))


def _encode_ef_kc_default() -> bytes:
    # 3GPP TS 31.102 §4.4.3 EF.Kc / EF.KcGPRS shape. Nine
    # bytes total:
    #
    #   Bytes 0..7   8-byte Kc ciphering key.
    #   Byte 8       Cipher Key Sequence Number (CKSN) per
    #                3GPP TS 24.008 §10.5.1.2.
    #
    # CKSN value 7 (binary 111) marks "no key available", i.e.
    # the modem must run AKA before encrypting traffic. We
    # default Kc to 8x 0x00 and CKSN to 0x07 so a freshly
    # provisioned card never advertises a stale key set.
    return b"\x00" * 8 + bytes((0x07,))


def _encode_ef_cfis_record() -> bytes:
    # 3GPP TS 31.102 §4.2.64 EF.CFIS - Call Forwarding
    # Indication Status. Linear-fixed, 16 bytes per record:
    #   Byte  0     MSP ID (0x01 default = subscription profile 1).
    #   Byte  1     CFU indicator status. Bit 1 set = CFU active;
    #               other bits RFU. Default 0x00 = no forwarding.
    #   Byte  2     TON / NPI byte (only valid when CFU active).
    #   Bytes 3..13 BCD-encoded forwarding-to dialling number,
    #               left-justified, padded with 0xF nibbles.
    #   Byte 14     CCP record id (0xFF = none).
    #   Byte 15     Ext7 record id (0xFF = none).
    # Default record: profile 1 selected, CFU off, dialling
    # number / extension placeholders all-FF so the modem can
    # write a real number via UPDATE RECORD without resizing.
    return (
        bytes((0x01,))           # MSP ID
        + bytes((0x00,))         # CFU indicator status (off)
        + b"\xFF" * 12           # TON/NPI + BCD digits (placeholder)
        + bytes((0xFF, 0xFF))    # CCP + Ext7 record ids
    )


def _attach_ready_usim_nodes(
    *,
    imsi: str,
    service_provider: str,
    mnc_length: int,
) -> list[SimProfileFsNode]:
    mcc_text, mnc_text = _mcc_mnc_from_imsi(imsi, mnc_length)
    plmn_bytes = _encode_plmn_3gpp(mcc_text, mnc_text) if len(mcc_text) == 3 else b"\xFF\xFF\xFF"

    invalidated_keys = b"\x07" + (b"\xFF" * 32)
    fplmn_entries = b"\xFF" * 12
    ehplmn_record = bytes(plmn_bytes)
    hplmnwact_record = _encode_ef_hplmnwact(plmn_bytes)
    start_hfn = b"\x00\x00\x00\x00\x00\x00"
    threshold = b"\x02\x00\x00\x02\x00\x00"
    access_classes = b"\x00\x04"
    ef_ecc_records = [b"\x11\xF2\xFF\x00", b"\x19\xF1\xFF\x00"]
    ef_ust_bytes = _encode_ef_ust_default()
    ef_spn_bytes = _encode_ef_spn(service_provider)
    ef_ad_bytes = bytes((0x00, 0x00, 0x00, mnc_length & 0x0F))
    ef_arr_record = bytes.fromhex("800101A40683010190A004840132")

    base: list[SimProfileFsNode] = [
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.ARR"),
            name="EF.ARR",
            kind="ef",
            fid="6F06",
            structure="linear-fixed",
            records=[ef_arr_record],
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.LI"),
            name="EF.LI",
            kind="ef",
            fid="6F05",
            structure="transparent",
            data=b"en",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.UST"),
            name="EF.UST",
            kind="ef",
            fid="6F38",
            structure="transparent",
            data=ef_ust_bytes,
            # USIM Service Table is provisioned by the issuer; modems
            # are read-only against it. TS 31.102 §4.2.8 lists UPDATE
            # at the "ADM" condition.
            write_acl="adm",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SPN"),
            name="EF.SPN",
            kind="ef",
            fid="6F46",
            structure="transparent",
            data=ef_spn_bytes,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.ACC"),
            name="EF.ACC",
            kind="ef",
            fid="6F78",
            structure="transparent",
            data=access_classes,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.ECC"),
            name="EF.ECC",
            kind="ef",
            fid="6FB7",
            structure="linear-fixed",
            records=ef_ecc_records,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.AD"),
            name="EF.AD",
            kind="ef",
            fid="6FAD",
            structure="transparent",
            data=ef_ad_bytes,
            # EF.AD carries the OFM bit and MNC length. TS 31.102 §4.2.18
            # lists UPDATE at "ADM" -- network attach must not be able
            # to flip the operator-mode flags via UPDATE BINARY.
            write_acl="adm",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.KEYS"),
            name="EF.KEYS",
            kind="ef",
            fid="6F08",
            structure="transparent",
            data=invalidated_keys,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.KeysPS"),
            name="EF.KeysPS",
            kind="ef",
            fid="6F09",
            structure="transparent",
            data=invalidated_keys,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.LOCI"),
            name="EF.LOCI",
            kind="ef",
            fid="6F7E",
            structure="transparent",
            data=_encode_ef_loci(plmn_bytes),
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.PSLOCI"),
            name="EF.PSLOCI",
            kind="ef",
            fid="6F73",
            structure="transparent",
            data=_encode_ef_psloci(plmn_bytes),
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.EPSLOCI"),
            name="EF.EPSLOCI",
            kind="ef",
            fid="6FE3",
            structure="transparent",
            data=_encode_ef_epsloci(plmn_bytes),
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.EPSNSC"),
            name="EF.EPSNSC",
            kind="ef",
            fid="6FE4",
            structure="transparent",
            data=b"",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.FPLMN"),
            name="EF.FPLMN",
            kind="ef",
            fid="6F7B",
            structure="transparent",
            data=fplmn_entries,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.EHPLMN"),
            name="EF.EHPLMN",
            kind="ef",
            fid="6FD9",
            structure="transparent",
            data=ehplmn_record,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.HPLMNwAcT"),
            name="EF.HPLMNwAcT",
            kind="ef",
            fid="6F62",
            structure="transparent",
            data=hplmnwact_record,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.PLMNwAcT"),
            name="EF.PLMNwAcT",
            kind="ef",
            fid="6F60",
            structure="transparent",
            data=b"\xFF" * 40,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.OPLMNwAcT"),
            name="EF.OPLMNwAcT",
            kind="ef",
            fid="6F61",
            structure="transparent",
            data=b"\xFF" * 40,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.PNN"),
            name="EF.PNN",
            kind="ef",
            fid="6FC5",
            structure="linear-fixed",
            records=[b"\xFF" * 20],
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.OPL"),
            name="EF.OPL",
            kind="ef",
            fid="6FC6",
            structure="linear-fixed",
            records=[b"\xFF" * 8],
        ),
        # 3GPP TS 31.102 §4.2.66 EF.SPDI - Service Provider
        # Display Information. Transparent EF gated
        # by EF.UST service 51. Default seed: empty SPDI list
        # (`A3 02 80 00`) so a modem reading the EF before the
        # operator pushes an SPDI provisioning record gets a
        # well-formed but empty TLV scaffold instead of `6A 82`.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SPDI"),
            name="EF.SPDI",
            kind="ef",
            fid="6FCD",
            structure="transparent",
            data=_encode_ef_spdi_default(),
        ),
        # 3GPP TS 31.102 §4.2.10 EF.GID1 - Group Identifier Level 1.
        # Used by MVNO / service-provider gating logic. The default
        # profile leaves the four-byte slot blank (0xFF) so a service
        # that compares against EF.GID1 falls through to "no group".
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.GID1"),
            name="EF.GID1",
            kind="ef",
            fid="6F3E",
            structure="transparent",
            data=b"\xFF" * 4,
            write_acl="adm",
        ),
        # 3GPP TS 31.102 §4.2.11 EF.GID2 - Group Identifier Level 2.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.GID2"),
            name="EF.GID2",
            kind="ef",
            fid="6F3F",
            structure="transparent",
            data=b"\xFF" * 4,
            write_acl="adm",
        ),
        # 3GPP TS 31.102 §4.2.27 EF.SMSP - Short Message Service
        # Parameters. Linear-fixed record set; the default profile
        # seeds a single 40-byte (12-byte alpha + 28-byte body) slot
        # with all fields marked "not provisioned" so a real modem
        # can UPDATE RECORD over it without the simulator stomping
        # the SC address it wants to advertise.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SMSP"),
            name="EF.SMSP",
            kind="ef",
            fid="6F42",
            structure="linear-fixed",
            records=[_encode_ef_smsp_record(alpha_length=12)],
        ),
        # 3GPP TS 31.102 §4.2.9 EF.SMSS - SMS Status. Two-byte
        # transparent EF carrying TP-MR + memory-capacity flag.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SMSS"),
            name="EF.SMSS",
            kind="ef",
            fid="6F43",
            structure="transparent",
            data=_encode_ef_smss_default(),
        ),
        # 3GPP TS 31.102 §4.2.40 EF.MSISDN - Mobile Subscriber
        # Number. Linear-fixed; the default profile seeds a single
        # 22-byte slot (8-byte alpha + 14-byte dial body) all-FF so
        # the modem can UPDATE RECORD over it once provisioning
        # supplies the MSISDN.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.MSISDN"),
            name="EF.MSISDN",
            kind="ef",
            fid="6F40",
            structure="linear-fixed",
            records=[_encode_ef_msisdn_record(alpha_length=8)],
        ),
        # 3GPP TS 31.102 §4.2.55 EF.MBI - Mailbox Identifier.
        # Linear-fixed; one record with voicemail pointing at
        # EF.MBDN slot 1 and the remaining mailbox types disabled.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.MBI"),
            name="EF.MBI",
            kind="ef",
            fid="6FC9",
            structure="linear-fixed",
            records=[_encode_ef_mbi_record()],
        ),
        # 3GPP TS 31.102 §4.2.56 EF.MBDN - Mailbox Dialling Numbers.
        # Linear-fixed; one blank 22-byte slot mirroring the
        # EF.MSISDN layout. UPDATE RECORD provisions the actual
        # voicemail dial string when the operator pushes it.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.MBDN"),
            name="EF.MBDN",
            kind="ef",
            fid="6FC7",
            structure="linear-fixed",
            records=[_encode_ef_mbdn_record(alpha_length=8)],
        ),
        # 3GPP TS 31.102 §4.2.57 EF.MWIS - Message Waiting
        # Indication Status. Linear-fixed; one record with no
        # waiting-message flags set and zero counters.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.MWIS"),
            name="EF.MWIS",
            kind="ef",
            fid="6FCA",
            structure="linear-fixed",
            records=[_encode_ef_mwis_record()],
        ),
        # 3GPP TS 31.102 §4.2.32 EF.LND - Last Number Dialled
        #. Cyclic, one 22-byte record (8-byte alpha +
        # 14-byte dial body), all-FF -- no last number dialled
        # yet. UPDATE RECORD mode 0x03 (previous) cycles new
        # entries through; the simulator's cyclic semantics keep
        # the most-recent record at the head and overwrite the
        # oldest in place.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.LND"),
            name="EF.LND",
            kind="ef",
            fid="6F44",
            structure="cyclic",
            records=[_encode_ef_lnd_record(alpha_length=8)],
        ),
        # 3GPP TS 31.102 §4.2.20 EF.ICI - Incoming Call Information
        #. Cyclic record store for the call-history
        # log. Default seed: one 30-byte all-FF record, modem
        # appends new entries via UPDATE RECORD mode 0x03.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.ICI"),
            name="EF.ICI",
            kind="ef",
            fid="6F80",
            structure="cyclic",
            records=[_encode_ef_ici_record(alpha_length=8)],
        ),
        # 3GPP TS 31.102 §4.2.21 EF.OCI - Outgoing Call Information
        #. Same shape as EF.ICI minus the unread byte;
        # the simulator carries the conservative full layout
        # because the FCP descriptor advertises the exact length.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.OCI"),
            name="EF.OCI",
            kind="ef",
            fid="6F81",
            structure="cyclic",
            records=[_encode_ef_oci_record(alpha_length=8)],
        ),
        # 3GPP TS 31.102 §4.2.22 EF.ICT - Incoming Call Timer
        #. Cyclic, 3-byte BE counter of cumulative
        # incoming-call seconds. Default zero.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.ICT"),
            name="EF.ICT",
            kind="ef",
            fid="6F82",
            structure="cyclic",
            records=[_encode_ef_ict_record()],
        ),
        # 3GPP TS 31.102 §4.2.23 EF.OCT - Outgoing Call Timer
        #. Cyclic, 3-byte BE counter of cumulative
        # outgoing-call seconds. Default zero.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.OCT"),
            name="EF.OCT",
            kind="ef",
            fid="6F83",
            structure="cyclic",
            records=[_encode_ef_oct_record()],
        ),
        # 3GPP TS 31.102 §4.2.25 EF.SMS - SMS message storage
        #. Linear-fixed, 176 bytes per record. The
        # default profile carries one free slot (status byte
        # 0x00, body 0xFF) so a modem can immediately STORE an
        # SMS without resizing the EF.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SMS"),
            name="EF.SMS",
            kind="ef",
            fid="6F3C",
            structure="linear-fixed",
            records=[_encode_ef_sms_record()],
        ),
        # 3GPP TS 31.102 §4.2.28 EF.SMSR - SMS Status Reports
        #. Linear-fixed, 30 bytes per record. Service 11
        # in EF.UST. Each record links back to the matching EF.SMS
        # row plus a 29-byte Status Report TPDU.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SMSR"),
            name="EF.SMSR",
            kind="ef",
            fid="6F47",
            structure="linear-fixed",
            records=[_encode_ef_smsr_record()],
        ),
        # 3GPP TS 31.102 §4.2.46 EF.SDN - Service Dialling Numbers
        #. Linear-fixed, 22 bytes per record (alpha 8 +
        # 14-byte dial body). Service 4 in EF.UST. Operators
        # provision shortcut codes (customer service, voicemail
        # access) into these records OTA.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SDN"),
            name="EF.SDN",
            kind="ef",
            fid="6F49",
            structure="linear-fixed",
            records=[_encode_ef_sdn_record(alpha_length=8)],
        ),
        # 3GPP TS 31.102 §4.2.84 EF.EHPLMNPI - Equivalent HPLMN
        # Presentation Indication. Service 71 in
        # EF.UST. One transparent byte; bit 1 controls whether
        # the modem displays every EHPLMN or only the HPLMN.
        # Default 0x00 = HPLMN only.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.EHPLMNPI"),
            name="EF.EHPLMNPI",
            kind="ef",
            fid="6FDB",
            structure="transparent",
            data=_encode_ef_ehplmnpi_default(),
        ),
        # 3GPP TS 31.102 §4.2.64 EF.CFIS - Call Forwarding
        # Indication Status. Service 49 in EF.UST.
        # Linear-fixed, 16 bytes per record. Default seed:
        # MSP ID 0x01, CFU off, BCD dial body all-FF.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.CFIS"),
            name="EF.CFIS",
            kind="ef",
            fid="6FCB",
            structure="linear-fixed",
            records=[_encode_ef_cfis_record()],
        ),
        # 3GPP TS 31.102 §4.2.81 EF.PSISMSC - Public Service
        # Identity of the SM-SC for SM-over-IP messaging
        #. Service 91 in EF.UST. Linear-fixed; one
        # 64-byte default record carrying a TS 23.003-shaped
        # SIP URI rooted in the simulator's test PLMN, so a
        # paired modem can resolve the SM-SC end-point without
        # external provisioning.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.PSISMSC"),
            name="EF.PSISMSC",
            kind="ef",
            fid="6FE5",
            structure="linear-fixed",
            records=[_encode_ef_psismsc_record()],
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.START_HFN"),
            name="EF.START_HFN",
            kind="ef",
            fid="6F5B",
            structure="transparent",
            data=start_hfn,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.THRESHOLD"),
            name="EF.THRESHOLD",
            kind="ef",
            fid="6F5C",
            structure="transparent",
            data=threshold,
        ),
        # 3GPP TS 31.102 §4.2.6 EF.HPPLMN - Higher Priority PLMN
        # search period. One byte: search timer in
        # 6-minute units (range 0x01..0xF1). The 0x05 default
        # corresponds to 30 minutes between HPLMN scans, the
        # interval most operator profiles ship.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.HPPLMN"),
            name="EF.HPPLMN",
            kind="ef",
            fid="6F31",
            structure="transparent",
            data=bytes((0x05,)),
        ),
        # 3GPP TS 31.102 §4.2.34 EF.NETPAR - Network parameters
        # cache. The 16-byte transparent body holds
        # ciphering / integrity / RAT bookkeeping that the modem
        # writes on detach so a subsequent attach can resume
        # without renegotiating. Default is all-FF -- no cached
        # parameters yet, mirroring a freshly issued card.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.NETPAR"),
            name="EF.NETPAR",
            kind="ef",
            fid="6FC4",
            structure="transparent",
            data=b"\xFF" * 16,
        ),
        # 3GPP TS 31.102 §4.2.86 EF.LRPLMNSI - Last RPLMN Selection
        # Indication. One byte: 0x00 = "first attempt
        # after power on" (default), 0x01 = "subsequent attempt"
        # (set after the modem's first PLMN selection succeeds).
        # Modems read it during power-up to decide between fast
        # / full PLMN scans; the default lets a new image take
        # the full-scan path.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.LRPLMNSI"),
            name="EF.LRPLMNSI",
            kind="ef",
            fid="6FDC",
            structure="transparent",
            data=bytes((0x00,)),
        ),
        # 3GPP TS 31.102 §4.2.24 EF.FDN - Fixed Dialling Numbers.
        # Linear-fixed, 26 bytes per record (12-byte alpha + 14-byte
        # dial body), 8 records seeded all-FF. EF.UST service 2
        # advertises FDN; without this entry the modem's FDN walk
        # (00A40804047FFF6F3B) hits 6A82 even though service is on.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.FDN"),
            name="EF.FDN",
            kind="ef",
            fid="6F3B",
            structure="linear-fixed",
            records=[_encode_ef_msisdn_record(alpha_length=12) for _ in range(8)],
        ),
        # 3GPP TS 31.102 §4.2.45 EF.EXT2 - FDN Extension. Linear-fixed,
        # 13 bytes per record. Operators provision long FDN tails by
        # chaining EXT2 records out of EF.FDN's last byte. Default
        # 8 empty records (status 00, 12-byte body all-FF) so a modem
        # following a chain hits a deterministic terminator.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.EXT2"),
            name="EF.EXT2",
            kind="ef",
            fid="6F4B",
            structure="linear-fixed",
            records=[bytes((0x00,)) + (b"\xFF" * 12) for _ in range(8)],
        ),
        # 3GPP TS 31.102 §4.2.45 EF.EXT3 - SDN Extension. Same shape
        # as EXT2; default 2 empty records mirroring the typical
        # "no chained SDN tails" provisioning.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.EXT3"),
            name="EF.EXT3",
            kind="ef",
            fid="6F4C",
            structure="linear-fixed",
            records=[bytes((0x00,)) + (b"\xFF" * 12) for _ in range(2)],
        ),
        # 3GPP TS 31.102 §4.2.56 EF.RPLMNAcTD - RPLMN Last used
        # Access Technology. Transparent record EF, 2 bytes per
        # record, default 4 bytes = 2 records of "no RAT cached"
        # (0x00 FF). Modems read this on cold boot to decide which
        # RAT to try first; a missing EF forces a slow scan.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.RPLMNAcTD"),
            name="EF.RPLMNAcTD",
            kind="ef",
            fid="6F65",
            structure="transparent",
            data=bytes.fromhex("00FF00FF"),
        ),
        # CPHS Phase 2 §B.4.1.1 EF.CPHS_INFO. Three bytes:
        #   Byte 0  CPHS phase: 0x01 = phase 1, 0x02 = phase 2.
        #   Byte 1  CPHS Service Table mandatory services bitmap.
        #   Byte 2  CPHS Service Table optional services bitmap.
        # Default seed advertises CPHS phase 2 with no extra services,
        # which is what most modems gate on before reading 6F14/6F15.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.CPHS_INFO"),
            name="EF.CPHS_INFO",
            kind="ef",
            fid="6F16",
            structure="transparent",
            data=bytes((0x02, 0x00, 0x00)),
        ),
        # CPHS Phase 2 §B.4.1.2 EF.ONString - Operator Name String.
        # Transparent, 16-byte alpha + 1-byte termination. Default
        # all-FF lets the modem fall back to EF.SPN / EF.PNN for the
        # display name.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.ONString"),
            name="EF.ONString",
            kind="ef",
            fid="6F14",
            structure="transparent",
            data=b"\xFF" * 17,
        ),
        # CPHS Phase 2 §B.4.2.1 EF.CSP - Customer Service Profile.
        # Transparent, 22 bytes describing service-group toggles
        # (call offering, SMS, value-added services, ...). Default
        # all-FF marks every toggle "as-shipped"; modems treat
        # unknown values conservatively.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.CSP"),
            name="EF.CSP",
            kind="ef",
            fid="6F15",
            structure="transparent",
            data=b"\xFF" * 22,
        ),
        # CPHS Phase 2 §B.4.1.3 EF.MAILBOX_NUMBERS. Linear-fixed
        # placeholder mailbox table. 4-byte alpha + 1-byte length
        # + 11-byte BCD + 1-byte TON/NPI + 6-byte CCP/EXT1; 1 empty
        # record so the modem's mailbox lookup terminates cleanly.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.MAILBOX_NUMBERS"),
            name="EF.MAILBOX_NUMBERS",
            kind="ef",
            fid="6F17",
            structure="linear-fixed",
            records=[b"\xFF" * 23],
        ),
    ]
    base.extend(_default_df_5gs_nodes(plmn_bytes=plmn_bytes))
    base.extend(_default_df_gsm_access_nodes())
    return base


def _default_df_gsm_access_nodes() -> list[SimProfileFsNode]:
    # 3GPP TS 31.102 §4.4.3 DF.GSM-ACCESS lives under ADF.USIM
    # at FID 5F3B. The DF holds the cached GSM / GPRS ciphering
    # keys that a modem reuses on inter-RAT fallback (5G/4G ->
    # 2G/2.5G). EF.UST already advertises service 27 ("GSM
    # access"), so a spec-conformant card MUST expose at least
    # EF.Kc and EF.KcGPRS or every Kc fetch hits 6A82.
    return [
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.GSM-ACCESS"),
            name="DF.GSM-ACCESS",
            kind="df",
            fid="5F3B",
        ),
        # 3GPP TS 31.102 §4.4.3.2 EF.Kc - 8-byte ciphering key
        # plus a 1-byte Cipher Key Sequence Number (CKSN). The
        # default seed advertises no cached key so the modem
        # always re-runs AKA before encrypting GSM traffic.
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.GSM-ACCESS", "EF.Kc"),
            name="EF.Kc",
            kind="ef",
            fid="4F20",
            structure="transparent",
            data=_encode_ef_kc_default(),
        ),
        # 3GPP TS 31.102 §4.4.3.3 EF.KcGPRS - same 9-byte
        # layout as EF.Kc but caches the GPRS-side ciphering
        # key. Default seed mirrors EF.Kc (no cached key).
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.GSM-ACCESS", "EF.KcGPRS"),
            name="EF.KcGPRS",
            kind="ef",
            fid="4F52",
            structure="transparent",
            data=_encode_ef_kc_default(),
        ),
    ]


def _default_df_5gs_nodes(*, plmn_bytes: bytes) -> list[SimProfileFsNode]:
    # DF.5GS lives under ADF.USIM at FID 5FC0 per TS 31.102 §4.4.11.
    # The simulator default leaves ciphered 5G state empty (modem
    # initialises it on attach) but materialises every EF a real
    # modem expects to find so READ BINARY against the FIDs returns
    # something deterministic instead of 6A82.
    suci_calc_info = bytes()  # populated when an SM-DP+ profile lands.
    routing_indicator = bytes.fromhex("00FF")  # default RI=0 + 0xFF padding
    five_g_loci = bytes(plmn_bytes) + b"\xFF" * 13  # GUAMI placeholder + status
    five_g_nsc = b"\xFF" * 60
    return [
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS"),
            name="DF.5GS",
            kind="df",
            fid="5FC0",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.5GS3GPPLOCI"),
            name="EF.5GS3GPPLOCI",
            kind="ef",
            fid="4F01",
            structure="transparent",
            data=five_g_loci,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.5GSN3GPPLOCI"),
            name="EF.5GSN3GPPLOCI",
            kind="ef",
            fid="4F02",
            structure="transparent",
            data=five_g_loci,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.5GS3GPPNSC"),
            name="EF.5GS3GPPNSC",
            kind="ef",
            fid="4F03",
            structure="linear-fixed",
            records=[five_g_nsc],
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.5GSN3GPPNSC"),
            name="EF.5GSN3GPPNSC",
            kind="ef",
            fid="4F04",
            structure="linear-fixed",
            records=[five_g_nsc],
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.5GAUTHKEYS"),
            name="EF.5GAUTHKEYS",
            kind="ef",
            fid="4F05",
            structure="transparent",
            data=b"",
            # KAUSF / KSEAF are derived during 5G AKA and must not be
            # writable by the modem -- TS 31.102 §4.4.11.5 puts UPDATE
            # at ADM.
            write_acl="adm",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.UAC-AIC"),
            name="EF.UAC-AIC",
            kind="ef",
            fid="4F06",
            structure="transparent",
            data=b"\x00\x00\x00\x00",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.SUCI_Calc_Info"),
            name="EF.SUCI_Calc_Info",
            kind="ef",
            fid="4F07",
            structure="transparent",
            data=suci_calc_info,
            # The SUCI calculation parameters (HN public key, scheme
            # priority list) are operator-issued; modems are read-only.
            write_acl="adm",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.OPL5G"),
            name="EF.OPL5G",
            kind="ef",
            fid="4F08",
            structure="linear-fixed",
            records=[b"\xFF" * 10],
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.SUPI_NAI"),
            name="EF.SUPI_NAI",
            kind="ef",
            fid="4F09",
            structure="transparent",
            data=b"",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.ROUTING-INDICATOR"),
            name="EF.ROUTING-INDICATOR",
            kind="ef",
            fid="4F0A",
            structure="transparent",
            data=routing_indicator,
            # TS 31.102 §4.4.11.6: UPDATE at ADM.
            write_acl="adm",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.URSP"),
            name="EF.URSP",
            kind="ef",
            fid="4F0B",
            structure="transparent",
            data=b"",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.TN3GPPSNN"),
            name="EF.TN3GPPSNN",
            kind="ef",
            fid="4F0C",
            structure="transparent",
            data=b"",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "DF.5GS", "EF.KAUSF-DERIVATION"),
            name="EF.KAUSF-DERIVATION",
            kind="ef",
            fid="4F16",
            structure="transparent",
            data=b"\x00" * 4,
            write_acl="adm",
        ),
    ]


def _encode_isim_uri_record(uri_bytes: bytes, *, record_length: int = 64) -> bytes:
    """3GPP TS 31.103 §4.2.2 EF.IMPU record encoding.

    Each record is a TLV with tag ``0x80`` whose value carries the
    SIP / TEL URI as UTF-8 bytes. Records are padded to a fixed
    width (default 64 bytes) with ``0xFF`` so the linear-fixed EF
    has predictable record boundaries that match the way
    commercial cards lay them out.
    """
    payload = bytes(uri_bytes or b"")
    if len(payload) > 0xFE:
        payload = payload[:0xFE]
    tlv_blob = bytes((0x80, len(payload))) + payload
    if len(tlv_blob) >= record_length:
        return tlv_blob[:record_length]
    return tlv_blob + b"\xFF" * (record_length - len(tlv_blob))


def _encode_isim_domain_record(domain: str) -> bytes:
    """3GPP TS 31.103 §4.2.4 EF.DOMAIN encoding (transparent).

    The body is a TLV ``80 LL <domain bytes>``. An empty / unset
    domain still produces a valid zero-length value so SELECT /
    READ BINARY do not fault on the file.
    """
    domain_bytes = str(domain or "").strip().encode("utf-8", "ignore")
    if len(domain_bytes) > 0xFE:
        domain_bytes = domain_bytes[:0xFE]
    return bytes((0x80, len(domain_bytes))) + domain_bytes


def _encode_isim_pcscf_record(address: str, *, record_length: int = 64) -> bytes:
    """3GPP TS 31.103 §4.2.8 EF.PCSCF record encoding.

    Each record is laid out as ``80 LL <type><address>`` where the
    type byte (``00``) marks the address as a FQDN per §4.2.8
    table 4.2.8-1. The remaining bytes are the FQDN as UTF-8.
    Records are padded to a fixed width (default 64 bytes) with
    ``0xFF`` so READ RECORD returns a deterministic length.
    """
    address_bytes = str(address or "").strip().encode("utf-8", "ignore")
    if len(address_bytes) > 0xFD:
        address_bytes = address_bytes[:0xFD]
    body = b"\x00" + address_bytes
    tlv_blob = bytes((0x80, len(body))) + body
    if len(tlv_blob) >= record_length:
        return tlv_blob[:record_length]
    return tlv_blob + b"\xFF" * (record_length - len(tlv_blob))


def _encode_ef_gbabp_default() -> bytes:
    # 3GPP TS 31.103 §4.2.10 EF.GBABP - GBA Bootstrapping
    # Parameters. Transparent EF carrying three TLV objects:
    #
    #   80 LL B-TID         Bootstrapping Transaction Identifier
    #   81 LL Ks_NAF        Derived NAF key
    #   82 LL Lifetime      Key lifetime
    #
    # On a freshly-issued card the EF is empty (no successful
    # GBA bootstrap has run yet). We seed three zero-length
    # TLVs so a modem that reads the EF before bootstrapping
    # gets a deterministic 6-byte view rather than ``6A 82``.
    # First successful bootstrap will UPDATE BINARY over this
    # placeholder with the real material.
    return bytes((0x80, 0x00, 0x81, 0x00, 0x82, 0x00))


def _encode_ef_gbanl_record(*, record_length: int = 28) -> bytes:
    # 3GPP TS 31.103 §4.2.11 EF.GBANL - GBA NAF List. Linear-
    # fixed; each record carries the NAF Key identifier
    # (NAF_ID + B-TID). Default seed is one all-FF placeholder
    # row; the modem populates the row pair-wise on subsequent
    # GBA bootstraps using UPDATE RECORD.
    return b"\xFF" * max(8, int(record_length))


def _extract_realm_from_impi(impi: str) -> str:
    """Best-effort home-realm extraction from a NAI-form IMPI.

    Per TS 23.003 §13, the IMPI is encoded as ``user@realm``; the
    realm portion is what EF.DOMAIN should advertise. If the IMPI
    is missing the ``@`` separator the simulator falls back to a
    deterministic default so the EF stays populated.
    """
    candidate = str(impi or "").strip()
    if "@" in candidate:
        realm = candidate.split("@", 1)[1].strip()
        if len(realm) > 0:
            return realm
    return "ims.mnc001.mcc999.3gppnetwork.org"


def _default_profile_image(
    iccid: str,
    imsi: str,
    impi: str,
    *,
    service_provider: str = "YggdraSIM",
    mnc_length: int = 2,
    minimal: bool = False,
) -> SimProfileImage:
    base_nodes: list[SimProfileFsNode] = [
        SimProfileFsNode(
            path=("MF", "EF.ICCID"),
            name="EF.ICCID",
            kind="ef",
            fid="2FE2",
            structure="transparent",
            data=encode_iccid_ef(iccid),
            sfi=0x02,
        ),
        SimProfileFsNode(
            path=("MF", "EF.PL"),
            name="EF.PL",
            kind="ef",
            fid="2F05",
            structure="transparent",
            data=b"en",
            sfi=0x05,
        ),
        SimProfileFsNode(
            path=("MF", "EF.ARR"),
            name="EF.ARR",
            kind="ef",
            fid="2F06",
            structure="linear-fixed",
            records=[bytes.fromhex("800101A40683010190A004840132")],
            sfi=0x06,
        ),
        SimProfileFsNode(
            path=("MF", "DF.TELECOM"),
            name="DF.TELECOM",
            kind="df",
            fid="7F10",
        ),
        # SAIP Profile Interoperability §9.4 / pySim ``FilesTelecom``:
        # DF.TELECOM exposes a local EF.ARR (6F06) carrying the access
        # rules referenced by every linear/cyclic EF underneath. A
        # modem reading 7F10/6F06 expects the same default rule shape
        # as the MF-side EF.ARR.
        SimProfileFsNode(
            path=("MF", "DF.TELECOM", "EF.ARR"),
            name="EF.ARR",
            kind="ef",
            fid="6F06",
            structure="linear-fixed",
            records=[bytes.fromhex("800101A40683010190A004840132")],
        ),
        # 3GPP TS 31.102 §4.4.2 / TS 31.103 §4.4.3 phonebook tree
        # rooted under DF.TELECOM. The DF.PHONEBOOK shell plus a
        # default EF.PBR (Phone Book Reference) record let a modem
        # walking 7F10/5F3A/4F30 land on a deterministic stub
        # instead of 6A82. The PBR record advertises an empty
        # phonebook (Type 1 list with zero references).
        SimProfileFsNode(
            path=("MF", "DF.TELECOM", "DF.PHONEBOOK"),
            name="DF.PHONEBOOK",
            kind="df",
            fid="5F3A",
        ),
        SimProfileFsNode(
            path=("MF", "DF.TELECOM", "DF.PHONEBOOK", "EF.PBR"),
            name="EF.PBR",
            kind="ef",
            fid="4F30",
            structure="linear-fixed",
            records=[b"\xFF" * 32],
        ),
        SimProfileFsNode(
            path=("MF", "DF.GSM"),
            name="DF.GSM",
            kind="df",
            fid="7F20",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM"),
            name="ADF.USIM",
            kind="adf",
            fid="7FF0",
            aid=USIM_AID,
            label="USIM",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.IMSI"),
            name="EF.IMSI",
            kind="ef",
            fid="6F07",
            structure="transparent",
            data=encode_imsi_ef(imsi),
            sfi=0x07,
            # EF.IMSI is provisioned by the operator/SM-DP+ and must
            # never be rewritten over a normal modem channel
            # (TS 31.102 §4.2.2 lists UPDATE at "ADM"). The simulator
            # mirrors this so AT+CRSM/UPDATE BINARY against 6F07 from
            # an unauthenticated logical channel is rejected with 6982.
            write_acl="adm",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.ISIM"),
            name="ADF.ISIM",
            kind="adf",
            fid="7FF2",
            aid=ISIM_AID,
            label="ISIM",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.ISIM", "EF.IMPI"),
            name="EF.IMPI",
            kind="ef",
            fid="6F02",
            structure="transparent",
            data=impi.encode("utf-8"),
        ),
        SimProfileFsNode(
            # 3GPP TS 31.103 §4.2.2 EF.IMPU (Public User Identity).
            # Linear-fixed, record format = TLV ``80 LL <URI bytes>``.
            # Two records are seeded: the canonical SIP URI form and
            # an additional TEL URI so STK applets that scan for an
            # E.164 alias still find one without provisioning.
            path=("MF", "ADF.ISIM", "EF.IMPU"),
            name="EF.IMPU",
            kind="ef",
            fid="6F04",
            structure="linear-fixed",
            records=[
                _encode_isim_uri_record(f"sip:{impi}".encode("utf-8")),
                _encode_isim_uri_record(b"tel:+1-555-0100"),
            ],
        ),
        SimProfileFsNode(
            # 3GPP TS 31.103 §4.2.4 EF.DOMAIN (Home Network Domain
            # Name). Transparent, content = TLV ``80 LL <domain>``.
            # The home realm is derived from the IMPI suffix when
            # available so the simulator stays consistent across
            # boots without dragging in a separate provisioning
            # field.
            path=("MF", "ADF.ISIM", "EF.DOMAIN"),
            name="EF.DOMAIN",
            kind="ef",
            fid="6F03",
            structure="transparent",
            data=_encode_isim_domain_record(_extract_realm_from_impi(impi)),
        ),
        SimProfileFsNode(
            # 3GPP TS 31.103 §4.2.5 EF.AD (Administrative Data).
            # Same 4-byte shape as the USIM-side EF.AD: byte 0 is
            # MS-Operation Mode, bytes 1..2 are Additional
            # Information (zero-padded), byte 3 is the MNC length.
            path=("MF", "ADF.ISIM", "EF.AD"),
            name="EF.AD",
            kind="ef",
            fid="6FAD",
            structure="transparent",
            data=bytes((0x00, 0x00, 0x00, mnc_length & 0x0F)),
        ),
        SimProfileFsNode(
            # 3GPP TS 31.103 §4.2.7 EF.IST (ISIM Service Table).
            # Bit-field, 1 byte per service group. The simulator
            # advertises the four core IMS services (P-CSCF
            # discovery, GBA, HTTP Digest, GBA-based local key
            # establishment) as available + activated by setting
            # the matching bits in byte 0.
            #
            # Byte 0 bit map (TS 31.103 §4.2.7):
            #   bit 1 -- service no. 1: P-CSCF address
            #   bit 2 -- service no. 2: GBA
            #   bit 3 -- service no. 3: HTTP Digest
            #   bit 4 -- service no. 4: GBA local key establishment
            #   bit 5 -- service no. 5: Support of P-CSCF Discovery
            #            for IMS Local Break Out
            #   bit 6 -- service no. 6: Short Message storage
            #   bit 7 -- service no. 7: Short Message status reports
            #   bit 8 -- service no. 8: Support for SM-over-IP
            path=("MF", "ADF.ISIM", "EF.IST"),
            name="EF.IST",
            kind="ef",
            fid="6F07",
            structure="transparent",
            data=bytes((0xFF,)),
        ),
        SimProfileFsNode(
            # 3GPP TS 31.103 §4.2.8 EF.PCSCF (P-CSCF Address).
            # Linear-fixed; each record carries a TLV
            # ``80 LL <address>`` where the address is encoded
            # with the same TON/NPI prefix as a SIP URI (UTF-8
            # bytes; the leading 0x00 reserves the byte for the
            # type indicator per §4.2.8).
            #
            # The seeded record points to a deterministic
            # ``pcscf.ims.<realm>`` so a paired modem can resolve
            # the entry-point CSCF without external provisioning.
            path=("MF", "ADF.ISIM", "EF.PCSCF"),
            name="EF.PCSCF",
            kind="ef",
            fid="6F09",
            structure="linear-fixed",
            records=[
                _encode_isim_pcscf_record(
                    "pcscf." + _extract_realm_from_impi(impi)
                ),
            ],
        ),
        # 3GPP TS 31.103 §4.2.10 EF.GBABP - GBA Bootstrapping
        # Parameters. Required because EF.IST
        # advertises GBA (service 2). Seeded with three empty
        # TLVs so the EF has a deterministic 6-byte default
        # before the first bootstrap runs.
        SimProfileFsNode(
            path=("MF", "ADF.ISIM", "EF.GBABP"),
            name="EF.GBABP",
            kind="ef",
            fid="6FD5",
            structure="transparent",
            data=_encode_ef_gbabp_default(),
        ),
        # 3GPP TS 31.103 §4.2.11 EF.GBANL - GBA NAF List
        #. Linear-fixed list of NAF_ID / B-TID
        # pairs. Default seed: one 28-byte all-FF placeholder
        # so the modem can UPDATE RECORD post-bootstrap
        # without the simulator pre-allocating per-NAF rows.
        SimProfileFsNode(
            path=("MF", "ADF.ISIM", "EF.GBANL"),
            name="EF.GBANL",
            kind="ef",
            fid="6FD7",
            structure="linear-fixed",
            records=[_encode_ef_gbanl_record(record_length=28)],
        ),
        # 3GPP TS 31.103 §4.2.13 EF.SMS - Short Message
        # storage in ISIM. Linear-fixed; 1-byte
        # status + 175-byte TPDU per record. Required because
        # EF.IST advertises service 6 (Short Message storage).
        # Default seed: one empty slot (0x00 status + FF
        # padding) so a modem reading record 1 before any SMS
        # has been stored gets a deterministic 176-byte view.
        SimProfileFsNode(
            path=("MF", "ADF.ISIM", "EF.SMS"),
            name="EF.SMS",
            kind="ef",
            fid="6F3C",
            structure="linear-fixed",
            records=[_encode_ef_sms_record()],
        ),
        # 3GPP TS 31.103 §4.2.14 EF.SMSS - SMS Status in
        # ISIM. Transparent, two bytes:
        #   Byte 0  Last-Used TP-MR (0x00 on issuance).
        #   Byte 1  SMS memory-capacity exceeded notification
        #           flag (0xFF = no notification owed).
        # Required by EF.IST service 6.
        SimProfileFsNode(
            path=("MF", "ADF.ISIM", "EF.SMSS"),
            name="EF.SMSS",
            kind="ef",
            fid="6F43",
            structure="transparent",
            data=_encode_ef_smss_default(),
        ),
        # 3GPP TS 31.103 §4.2.15 EF.SMSR - SMS Status Reports
        # in ISIM. Linear-fixed; 1-byte link to
        # EF.SMS record + 29-byte status report TPDU.
        # Required by EF.IST service 7.
        SimProfileFsNode(
            path=("MF", "ADF.ISIM", "EF.SMSR"),
            name="EF.SMSR",
            kind="ef",
            fid="6F47",
            structure="linear-fixed",
            records=[_encode_ef_smsr_record()],
        ),
    ]

    if minimal:
        base_nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.USIM", "EF.AD"),
                name="EF.AD",
                kind="ef",
                fid="6FAD",
                structure="transparent",
                data=bytes((0x00, 0x00, 0x00, mnc_length & 0x0F)),
            )
        )
        return SimProfileImage(
            iccid=iccid,
            imsi=imsi,
            impi=impi,
            nodes=base_nodes,
        )

    attach_nodes = _attach_ready_usim_nodes(
        imsi=imsi,
        service_provider=service_provider,
        mnc_length=mnc_length,
    )
    return SimProfileImage(
        iccid=iccid,
        imsi=imsi,
        impi=impi,
        nodes=base_nodes + attach_nodes,
    )


def _register_node(nodes: dict[str, SimFileNode], node: SimFileNode) -> None:
    nodes[node.node_id] = node
    if len(node.parent_id) > 0 and node.parent_id in nodes:
        nodes[node.parent_id].children.append(node.node_id)


def _build_name_path_index(nodes: dict[str, SimFileNode]) -> dict[tuple[str, ...], str]:
    index: dict[tuple[str, ...], str] = {}

    def walk(node_id: str, path: tuple[str, ...]) -> None:
        node = nodes[node_id]
        index[path] = node_id
        for child_id in node.children:
            child = nodes.get(child_id)
            if child is None:
                continue
            walk(child_id, path + (child.name,))

    if "3F00" in nodes:
        walk("3F00", ("MF",))
    return index


def _resolve_active_profile(state: SimCardState) -> SimProfileEntry | None:
    active = None
    active_aid = str(state.active_profile_aid or "").strip().upper()
    if len(active_aid) > 0:
        for profile in state.profiles:
            if profile.aid.upper() == active_aid:
                active = profile
                break
    if active is None:
        for profile in state.profiles:
            if str(profile.state).strip().lower() == "enabled":
                active = profile
                break
    state.active_profile_aid = active.aid if active is not None else ""
    return active


def apply_security_domain_config(state: SimCardState) -> None:
    _apply_security_domain_node(state.base_nodes, "ISDR", state.isdr_aid, state.isdr_label)
    _apply_security_domain_node(state.base_nodes, "ECASD", state.ecasd_aid, state.ecasd_label)
    _apply_security_domain_node(state.base_nodes, "MNO_SD", state.mno_sd_aid, state.mno_sd_label)
    if len(state.nodes) > 0:
        _apply_security_domain_node(state.nodes, "ISDR", state.isdr_aid, state.isdr_label)
        _apply_security_domain_node(state.nodes, "ECASD", state.ecasd_aid, state.ecasd_label)
        _apply_security_domain_node(state.nodes, "MNO_SD", state.mno_sd_aid, state.mno_sd_label)


def _apply_security_domain_node(
    nodes: dict[str, SimFileNode],
    node_id: str,
    aid_hex: str,
    label: str,
) -> None:
    node = nodes.get(node_id)
    if node is None:
        return
    if len(str(aid_hex or "").strip()) > 0:
        node.aid = str(aid_hex).strip().upper()
    if len(str(label or "").strip()) > 0:
        node.label = str(label).strip()


def rebuild_runtime_filesystem(state: SimCardState) -> None:
    previous_node_id = str(state.current_node_id or "3F00")
    base_nodes = state.base_nodes if len(state.base_nodes) > 0 else state.nodes
    state.nodes = copy.deepcopy(base_nodes)
    nodes = state.nodes
    path_index = _build_name_path_index(nodes)

    for index, profile in enumerate(state.profiles, start=1):
        label = f"ISD-P{index}"
        _register_node(
            nodes,
            SimFileNode(
                node_id=f"ISDP::{profile.aid.upper()}",
                name=label,
                kind="adf",
                aid=profile.aid,
                label=label,
                parent_id="ISDR",
            ),
        )

    active_profile = _resolve_active_profile(state)
    active_image = active_profile.profile_image if active_profile is not None else None
    if active_profile is not None:
        if len(active_profile.iccid) > 0:
            state.iccid = active_profile.iccid
        if len(active_profile.imsi) > 0:
            state.imsi = active_profile.imsi
        if active_image is not None:
            if len(active_image.iccid) > 0:
                state.iccid = active_image.iccid
            if len(active_image.imsi) > 0:
                state.imsi = active_image.imsi
            for image_node in sorted(active_image.nodes, key=lambda item: (len(item.path), item.path)):
                if len(image_node.path) <= 1 or image_node.path[0] != "MF":
                    continue
                parent_id = path_index.get(image_node.path[:-1])
                if parent_id is None:
                    continue
                node = SimFileNode(
                    node_id=_profile_path_node_id(image_node.path),
                    name=image_node.name,
                    kind=image_node.kind,
                    fid=image_node.fid,
                    aid=image_node.aid,
                    label=image_node.label,
                    parent_id=parent_id,
                    structure=image_node.structure,
                    data=bytes(image_node.data),
                    records=[bytes(record) for record in image_node.records],
                    sfi=image_node.sfi,
                    write_acl=str(getattr(image_node, "write_acl", "always") or "always"),
                    lifecycle_state=int(getattr(image_node, "lifecycle_state", 0x05) or 0x05) & 0xFF,
                    link_path=tuple(getattr(image_node, "link_path", ()) or ()),
                )
                _register_node(nodes, node)
                path_index[image_node.path] = node.node_id

    # If the BPP already shipped an EF.DIR via the active profile image
    # we must not clobber it: TCA Profile Interoperability §3.5 expects
    # the issuer-provided record set (AIDs, labels, padding) to surface
    # verbatim. The active image stores EF.DIR under a path-derived
    # ``PROFILE::`` node_id, so the canonical lookup is via path_index
    # rather than by raw FID.
    ef_dir_path = ("MF", "EF.DIR")
    ef_dir_node_id = path_index.get(ef_dir_path)
    bpp_supplied_efdir = False
    if ef_dir_node_id is not None:
        existing_dir = nodes.get(ef_dir_node_id)
        if existing_dir is not None and len(existing_dir.records) > 0:
            bpp_supplied_efdir = True

    def _resolve_dir_aid(path: tuple[str, ...], default_aid: str) -> str:
        node_id = path_index.get(path)
        if node_id is None:
            return default_aid
        node = nodes.get(node_id)
        if node is None:
            return default_aid
        return str(node.aid or default_aid)

    dir_records: list[bytes] = []
    if bpp_supplied_efdir is False:
        for path, default_aid, label in (
            (("MF", "ADF.USIM"), USIM_AID, "USIM"),
            (("MF", "ADF.ISIM"), ISIM_AID, "ISIM"),
            (("MF", "ISD-R"), str(state.isdr_aid or ISDR_AID), str(state.isdr_label or "ISDR")),
            (("MF", "ECASD"), str(state.ecasd_aid or ECASD_AID), str(state.ecasd_label or "ECASD")),
            (("MF", "MNO-SD"), str(state.mno_sd_aid or MNO_SD_AID), str(state.mno_sd_label or "MNO-SD")),
        ):
            if path in path_index:
                dir_records.append(_app_record(_resolve_dir_aid(path, default_aid), label))
    if len(dir_records) > 0:
        # Linear-fixed EFs must have fixed-size records (TS 102 221 §8.2).
        # Pad every slot with 0xFF to the longest application record so
        # READ RECORD returns a deterministic record_length regardless of
        # which slot the terminal reads. This matches the zero-padded
        # record layout observed on commercial UICC references.
        max_record_length = max(len(record) for record in dir_records)
        padded_records = [
            record + b"\xFF" * (max_record_length - len(record))
            for record in dir_records
        ]
        _register_node(
            nodes,
            SimFileNode(
                node_id="2F00",
                name="EF.DIR",
                kind="ef",
                fid="2F00",
                parent_id="3F00",
                structure="linear-fixed",
                records=padded_records,
                sfi=0x1E,
            ),
        )

    if ("MF", "EF.ICCID") not in path_index and len(state.iccid) > 0:
        _register_node(
            nodes,
            SimFileNode(
                node_id="2FE2",
                name="EF.ICCID",
                kind="ef",
                fid="2FE2",
                parent_id="3F00",
                structure="transparent",
                data=encode_iccid_ef(state.iccid),
                sfi=0x02,
            ),
        )

    # 3GPP TS 51.011 §10 mandates that a UICC offering a USIM
    # application also exposes the legacy GSM file system at MF /
    # DF.GSM (FID 7F20). Real-world dual-mode SIMs always present
    # this DF so a 2G-style modem cold-attach (CLA=0xA0 SELECT 7F20)
    # succeeds even when the operator's BPP did not explicitly carve
    # one out via genericFileManagement. If the active profile's
    # image stream did not land a 7F20 node under MF, synthesise an
    # empty stub. EFs under DF.GSM (EF.IMSI, EF.LOCI, EF.Kc, ...)
    # only matter once the modem actually descends into the DF,
    # which current basebands rarely do once they discover ADF.USIM
    # via EF.DIR. The stub satisfies the probe and unblocks the
    # cold attach.
    if ("MF", "DF.GSM") not in path_index and "3F00" in nodes:
        df_gsm_node_id = "DF_GSM_LEGACY"
        if df_gsm_node_id not in nodes:
            _register_node(
                nodes,
                SimFileNode(
                    node_id=df_gsm_node_id,
                    name="DF.GSM",
                    kind="df",
                    fid="7F20",
                    parent_id="3F00",
                ),
            )
            path_index[("MF", "DF.GSM")] = df_gsm_node_id

    # 3GPP TS 31.102 Annex H "EFs shared between SIM and USIM" /
    # TCA Profile Interoperability §3.5.5: an issuer is free to
    # ship a single physical copy of any of the listed EFs (FID
    # 6Fxx -- IMSI, AD, ECC, LOCI, FPLMN, ...) under DF.GSM and
    # leave the same-FID EF under ADF.USIM empty. The card is
    # then expected to "share" the bytes between the two DF
    # contexts so a 5G/4G modem reading EF.IMSI from ADF.USIM
    # sees identical data to a 2G modem reading it from DF.GSM.
    # The user's BPP exercises exactly this layout: 6F07 / 6FAD
    # are populated only under DF.GSM. Mirror the bytes here, but
    # only when the ADF.USIM-side EF is genuinely empty (so an
    # operator that *did* ship distinct USIM-side content keeps
    # it intact).
    # SAIP / TCA Profile Interoperability v2.3.1 §8.3.5 explicit
    # ``Fcp.linkPath`` aliases. Operator BPPs commonly carve out a
    # template EF inside ADF.USIM / ADF.ISIM whose ``linkPath``
    # walks to the canonical EF under DF.GSM (7F20) or DF.TELECOM
    # (7F10). Resolve those aliases first so the issuer's explicit
    # intent always wins over the convention-based Annex H mirror
    # and the SAIP template defaults that follow.
    _apply_explicit_file_links_from_profile(nodes, path_index)

    _mirror_shared_efs_between_df_gsm_and_adf_usim(nodes, path_index)

    # TCA Profile Interoperability §3.5 / pySim ``FilesUsimMandatoryV2``,
    # ``FilesUsimOptionalV3``, ``FilesIsimMandatory``, ``FilesAtMF``,
    # ``FilesTelecom`` etc. ship a default-content pattern for every
    # template-defined EF (e.g. ``EF.AD = 00000002``,
    # ``EF.HPPLMN = 0A``, ``EF.PSLOCI = FFFFFFFFFF...0000FF01``).
    # An operator BPP that only carves out the FCP shell -- because
    # the issuer expects the card to materialise the template
    # default at runtime -- ends up with empty ``data`` / ``records``
    # in our parsed image, exactly the symptom that produces
    # ``9000`` with no body to a modem read. Apply the SAIP template
    # default last so issuer-supplied content (BPP overrides + Annex
    # H mirror) always wins, but otherwise EFs come up with the
    # bytes the spec says they should.
    _apply_saip_template_defaults_to_runtime(nodes, path_index)

    # SAIP §5.5 / §5.6 / §5.7: project the issuer-supplied PIN/PUK
    # table, GP Security Domain registry and OTA RFM bindings from the
    # active profile's image onto the runtime card state. Done here so
    # the same path that renders the file system also keeps the
    # secrets / GP registry / OTA dispatch tables coherent with the
    # currently enabled Profile.
    if active_image is not None:
        _apply_chv_table_from_profile(state, active_image.pin_codes, active_image.puk_codes)
        _apply_security_domains_from_profile(state, active_image.security_domains)
        _apply_rfm_instances_from_profile(state, active_image.rfm_instances)

    # SGP.32 §3.5 / TS 31.102 §4.2.48: the active SAIP profile may ship
    # an EF.ACL (FID 6F57) carrying one or more APNs. The first record
    # there outranks the env / workspace fallbacks for the IPA-poll
    # bearer description so the IPA polls the eIM through the cellular
    # context the BPP commissioned. ``_extract_acl_apn`` is idempotent
    # and silently no-ops when the EF is missing or malformed.
    _apply_profile_apn_to_ipa_poll(state, nodes, path_index)

    state.current_node_id = previous_node_id if previous_node_id in nodes else "3F00"


# 3GPP TS 31.102 Annex H Table H.1 "EFs shared between SIM and
# USIM". Each entry lists a 2-byte FID that, when present in both
# DF.GSM (7F20) and ADF.USIM, must surface identical content.
# Operators routinely ship the data only on the DF.GSM side, so the
# ADF.USIM-side EF is materialised as an empty FCP and relies on
# the card to mirror bytes from DF.GSM at runtime.
_TS_31_102_ANNEX_H_SHARED_EFS: frozenset[str] = frozenset(
    {
        "6F05",  # EF.LI       (Language Indication)
        "6F07",  # EF.IMSI
        "6F08",  # EF.Keys     (CK / IK / KSI; legacy GSM cipher key map)
        "6F09",  # EF.KeysPS   (CK_PS / IK_PS / KSI_PS)
        "6F31",  # EF.HPLMN    (HPLMN search period)
        "6F37",  # EF.ACMmax
        "6F38",  # EF.UST / EF.SST
        "6F39",  # EF.ACM
        "6F3E",  # EF.GID1
        "6F3F",  # EF.GID2
        "6F41",  # EF.PUCT
        "6F46",  # EF.SPN
        "6F60",  # EF.PLMNwAcT (USIM) / EF.PLMNsel (SIM)
        "6F61",  # EF.OPLMNwAcT
        "6F62",  # EF.HPLMNwAcT
        "6F73",  # EF.PSLOCI
        "6F78",  # EF.ACC      (Access Control Class)
        "6F7B",  # EF.FPLMN
        "6F7E",  # EF.LOCI
        "6FAD",  # EF.AD       (Administrative Data)
        "6FB7",  # EF.ECC      (Emergency Call Codes)
        "6FC4",  # EF.NETPAR
        "6FC5",  # EF.PNN
        "6FC6",  # EF.OPL
        "6FC7",  # EF.MBDN
        "6FCB",  # EF.CFIS
        "6FE3",  # EF.EPSLOCI
        "6FE4",  # EF.EPSNSC
    }
)


def _mirror_shared_efs_between_df_gsm_and_adf_usim(
    nodes: dict[str, SimFileNode],
    path_index: dict[tuple[str, ...], str],
) -> None:
    """Copy issuer-supplied data from DF.GSM/<FID> to every same-FID
    EF under any ADF.USIM-rooted subtree when the USIM-side EF is
    empty.

    This implements the TS 31.102 Annex H "shared EF" pattern that
    real SIM/USIM dual-mode cards offer transparently to the modem.
    The mirror is one-way (DF.GSM -> USIM) and only fires when the
    USIM-side EF carries no data and no records, so an issuer that
    deliberately provisioned distinct USIM-side bytes is never
    overwritten.

    The list of mirrorable FIDs is gated by
    ``_TS_31_102_ANNEX_H_SHARED_EFS`` so unrelated 6Fxx EFs that
    happen to coexist under both DFs (e.g. operator-private files
    that the card vendor placed in DF.GSM but reused with different
    semantics in USIM) are left alone.
    """
    df_gsm_node_id = path_index.get(("MF", "DF.GSM"))
    if df_gsm_node_id is None:
        return
    df_gsm_node = nodes.get(df_gsm_node_id)
    if df_gsm_node is None:
        return

    df_gsm_efs_by_fid: dict[str, SimFileNode] = {}
    for child_id in df_gsm_node.children:
        child = nodes.get(child_id)
        if child is None:
            continue
        if child.kind != "ef":
            continue
        fid_upper = str(child.fid or "").strip().upper()
        if fid_upper in _TS_31_102_ANNEX_H_SHARED_EFS:
            df_gsm_efs_by_fid[fid_upper] = child
    if len(df_gsm_efs_by_fid) == 0:
        return

    adf_roots: list[str] = []
    for path_tuple, node_id in path_index.items():
        if len(path_tuple) != 2 or path_tuple[0] != "MF":
            continue
        candidate = nodes.get(node_id)
        if candidate is None or candidate.kind != "adf":
            continue
        if candidate.label.upper() != "USIM" and "USIM" not in candidate.name.upper():
            continue
        adf_roots.append(node_id)
    if len(adf_roots) == 0:
        return

    def _walk_efs(root_id: str):
        stack: list[str] = [root_id]
        while len(stack) > 0:
            current_id = stack.pop()
            current = nodes.get(current_id)
            if current is None:
                continue
            for child_id in list(current.children):
                child = nodes.get(child_id)
                if child is None:
                    continue
                if child.kind in ("df", "adf"):
                    stack.append(child_id)
                elif child.kind == "ef":
                    yield child

    for adf_root_id in adf_roots:
        for usim_ef in _walk_efs(adf_root_id):
            fid_upper = str(usim_ef.fid or "").strip().upper()
            source = df_gsm_efs_by_fid.get(fid_upper)
            if source is None:
                continue
            usim_has_payload = (
                len(bytes(usim_ef.data or b"")) > 0
                or any(len(bytes(record or b"")) > 0 for record in usim_ef.records)
            )
            if usim_has_payload:
                continue
            usim_ef.data = bytes(source.data or b"")
            usim_ef.records = [bytes(record or b"") for record in source.records]
            usim_ef.structure = str(source.structure or usim_ef.structure)


def _resolve_link_path_target(
    nodes: dict[str, SimFileNode],
    path_index: dict[tuple[str, ...], str],
    link_path: tuple[str, ...],
) -> SimFileNode | None:
    """Walk a SAIP §8.3.5 ``linkPath`` (sequence of 2-byte FIDs) from
    the MF down to the file it points at and return the matching
    ``SimFileNode``, or ``None`` if the path cannot be resolved.

    The resolution is MF-rooted: each FID in ``link_path`` is a child
    of the previously-resolved DF/ADF. SAIP allows the path to be
    rooted at a temporary ADF FID instead of the MF; that variant is
    not exercised by current operator BPPs and would need a separate
    pass that maps temp FIDs to ADF nodes via ``ADF.dfName``. When
    the first FID is ``3F00`` we transparently skip it -- some BPPs
    encode the absolute root explicitly.
    """
    if len(link_path) == 0:
        return None
    mf_id = path_index.get(("MF",))
    if mf_id is None:
        return None
    cursor = nodes.get(mf_id)
    if cursor is None:
        return None
    fids = list(link_path)
    if len(fids) > 0 and fids[0].upper() == "3F00":
        fids = fids[1:]
    for fid_token in fids:
        fid_target = str(fid_token or "").strip().upper()
        if len(fid_target) == 0:
            return None
        next_node: SimFileNode | None = None
        for child_id in list(cursor.children):
            child = nodes.get(child_id)
            if child is None:
                continue
            if str(child.fid or "").strip().upper() == fid_target:
                next_node = child
                break
        if next_node is None:
            return None
        cursor = next_node
    return cursor


def _apply_explicit_file_links_from_profile(
    nodes: dict[str, SimFileNode],
    path_index: dict[tuple[str, ...], str],
) -> None:
    """Resolve every node carrying a non-empty ``link_path`` and copy
    the target file's content into the source node.

    SAIP / TCA Profile Interoperability v2.3.1 §8.3.5: an EF (or DF
    in the ``dfLinkSupport`` capability) may declare ``Fcp.linkPath``
    to alias a file located elsewhere in the file system. Operator
    BPPs use this extensively to delegate the canonical content of
    EF.IMSI / EF.SPN / EF.AD / EF.HPPLMN / etc. to ``DF.GSM`` and
    EF.SMS / EF.SMSP / EF.FDN / EF.MSISDN to ``DF.TELECOM``, while
    still presenting the EF under ``ADF.USIM`` (or ``ADF.ISIM``) so
    the modem can read it via the application-rooted SELECT path.

    The pass is idempotent and respects three invariants:

    1. Issuer-supplied content always wins. If the source EF already
       carries ``data`` or any non-empty record the link is treated as
       a creation-time hint that has been overridden and leave the
       source untouched. Same rule the on-card link resolver in real
       cards follows after CREATE FILE has materialised content.
    2. Cycles are detected and broken. If ``A`` links to ``B`` which
       links back to ``A`` we resolve at most one hop -- the
       ``link_path`` on the resolved target is ignored for the copy.
    3. Unresolved targets are silent. A link that walks to a FID
       that has not been registered yet (because the BPP layered
       it after the link-bearing slot or because the issuer omitted
       it entirely) is left as-is so the Annex H mirror or SAIP
       template default fill-in can take over downstream.

    The pass copies ``data``, ``records``, ``structure``, and (when
    the source did not learn one from the FCP) ``sfi``. Other FCP
    metadata (lifecycle state, write_acl) is *not* copied: those
    properties are issuer policy on the link slot itself, not on
    the underlying file.
    """
    for node_id in list(nodes.keys()):
        node = nodes.get(node_id)
        if node is None:
            continue
        link_path = tuple(getattr(node, "link_path", ()) or ())
        if len(link_path) == 0:
            continue
        # Issuer-supplied content wins -- the link was a creation
        # hint and the BPP layered actual bytes on top of the slot.
        if len(bytes(node.data or b"")) > 0 or any(len(bytes(rec or b"")) > 0 for rec in node.records):
            continue
        target = _resolve_link_path_target(nodes, path_index, link_path)
        if target is None:
            continue
        # Self-link guard: a link slot resolving back to itself
        # would be a no-op copy but we still bail out so the
        # downstream defaults pass can synthesise template content
        # for the slot if needed.
        if target.node_id == node.node_id:
            continue
        node.data = bytes(target.data or b"")
        node.records = [bytes(record or b"") for record in target.records]
        target_structure = str(target.structure or "").strip()
        if len(target_structure) > 0:
            node.structure = target_structure
        if node.sfi is None and target.sfi is not None:
            node.sfi = int(target.sfi) & 0x1F


# (parent_DF_runtime_name, FID_hex_uppercase) -> pySim FileTemplate.
# Built lazily on first use because importing pySim's template module
# instantiates a chain of ProfileTemplate subclasses and we want that
# cost paid once per process, not once per ``rebuild_runtime_filesystem``
# call (which fires on every profile rotation).
_SAIP_TEMPLATE_DEFAULTS_CACHE: dict[tuple[str, str], object] | None = None

# Mapping (pySim ProfileTemplate class -> parent DF runtime label).
# The label matches the ``SimFileNode.name`` we register at runtime
# for the corresponding container DF, so a runtime EF whose
# ``parent.name`` resolves to e.g. ``ADF.USIM`` looks up directly
# against ``("ADF.USIM", "6FAD")``. Templates that ``extends`` a
# parent template are intentionally listed too: pySim only parents
# the optional EFs to the mandatory base DF in-memory, the parent
# label that the runtime sees is identical (``ADF.USIM`` /
# ``ADF.ISIM``) so we deduplicate via ``setdefault``.
_SAIP_TEMPLATE_PARENTS: tuple[tuple[str, str], ...] = (
    ("FilesAtMF", "MF"),
    ("FilesUsimMandatory", "ADF.USIM"),
    ("FilesUsimMandatoryV2", "ADF.USIM"),
    ("FilesUsimOptional", "ADF.USIM"),
    ("FilesUsimOptionalV2", "ADF.USIM"),
    ("FilesUsimOptionalV3", "ADF.USIM"),
    ("FilesIsimMandatory", "ADF.ISIM"),
    ("FilesIsimOptional", "ADF.ISIM"),
    ("FilesIsimOptionalv2", "ADF.ISIM"),
    ("FilesUsimDfGsmAccess", "DF.GSM-ACCESS"),
    ("FilesUsimDf5GS", "DF.5GS"),
    ("FilesUsimDf5GSv2", "DF.5GS"),
    ("FilesUsimDf5GSv3", "DF.5GS"),
    ("FilesUsimDf5GSv4", "DF.5GS"),
    ("FilesUsimDfSaip", "DF.SAIP"),
    ("FilesTelecom", "DF.TELECOM"),
)


def _load_saip_template_defaults_registry() -> dict[tuple[str, str], object]:
    """Materialise the ``(parent_label, FID) -> FileTemplate`` map the
    SAIP-template default consumer needs.

    Lazy / cached because importing ``pySim.esim.saip.templates`` is
    not free and the registry is pure data once built.
    """
    global _SAIP_TEMPLATE_DEFAULTS_CACHE
    if _SAIP_TEMPLATE_DEFAULTS_CACHE is not None:
        return _SAIP_TEMPLATE_DEFAULTS_CACHE
    registry: dict[tuple[str, str], object] = {}
    try:
        import pySim.esim.saip.templates as saip_templates
    except Exception:  # pragma: no cover - defensive: pySim missing
        _SAIP_TEMPLATE_DEFAULTS_CACHE = registry
        return registry
    for class_name, parent_label in _SAIP_TEMPLATE_PARENTS:
        tpl_class = getattr(saip_templates, class_name, None)
        if tpl_class is None:
            continue
        files = getattr(tpl_class, "files", []) or []
        for file_template in files:
            fid = getattr(file_template, "fid", None)
            if fid is None:
                continue
            file_type = getattr(file_template, "file_type", None)
            if file_type in ("MF", "DF", "ADF"):
                continue
            # Skip templates whose ``ppath`` puts them under a
            # nested DF; the registry keys parent labels by name so
            # those would otherwise be filed against the *outer*
            # container and shadow the proper sub-DF entries.
            ppath = getattr(file_template, "ppath", []) or []
            if len(ppath) > 0:
                continue
            fid_hex = "%04X" % int(fid)
            registry.setdefault((parent_label, fid_hex), file_template)
    _SAIP_TEMPLATE_DEFAULTS_CACHE = registry
    return registry


def _expand_template_default(file_template: object, length: int) -> bytes:
    """Wrapper around pySim's ``FileTemplate.expand_default_value_pattern``
    that returns ``b""`` instead of raising when the pattern is
    malformed or zero-length, so a single dodgy template entry does
    not abort the whole runtime fill-in pass.
    """
    try:
        expander = getattr(file_template, "expand_default_value_pattern", None)
        if expander is None:
            return b""
        result = expander(length)
        if isinstance(result, (bytes, bytearray, memoryview)):
            return bytes(result)
    except Exception:  # pragma: no cover - defensive
        return b""
    return b""


def _apply_saip_template_defaults_to_runtime(
    nodes: dict[str, SimFileNode],
    path_index: dict[tuple[str, ...], str],
) -> None:
    """Fill SAIP template default values, SFIs and structures into
    every EF that came out of the BPP layering / Annex H mirror with
    no concrete content.

    Lookups key on ``(parent_DF_runtime_name, FID_hex_uppercase)``.
    The parent DF name matches what ``SimFileNode.name`` carries at
    runtime: ``MF``, ``ADF.USIM``, ``ADF.ISIM``, ``DF.TELECOM``, ...
    Anything not in the curated `_SAIP_TEMPLATE_PARENTS` set is left
    alone, including operator-private files that happen to live at
    a 6Fxx FID overlapping a TS 31.102 slot.

    The pass enforces three invariants:

    1. EFs whose pySim ``FileTemplate`` lists ``content_rqd=True``
       are never auto-populated. These cover IMSI, UST, SPN, ECC,
       GID1/2, ACC, EST and a handful of other security- or
       identity-relevant slots that the issuer must supply.
       Defaulting them would mask a broken BPP and let the modem
       attach with stale lab IMSIs.
    2. Issuer bytes (BPP overrides or Annex H mirror) win. The pass
       only fires when ``data`` is empty *and* every record is
       empty.
    3. SFIs and structures from the template are copied in even
       when the issuer supplied content -- they are FCP-level
       metadata, not file payload, and a missing SFI silently
       breaks ``READ BINARY`` with ``P1`` short-form selection
       (TS 102 221 §11.1.4).
    """
    registry = _load_saip_template_defaults_registry()
    if len(registry) == 0:
        return

    for node in nodes.values():
        if node.kind != "ef":
            continue
        parent = nodes.get(node.parent_id)
        if parent is None:
            continue
        parent_label = str(parent.name or "").strip()
        if len(parent_label) == 0:
            continue
        fid_hex = str(node.fid or "").strip().upper()
        if len(fid_hex) == 0:
            continue
        template = registry.get((parent_label, fid_hex))
        if template is None:
            continue

        template_sfi = getattr(template, "sfi", None)
        if node.sfi is None and template_sfi is not None:
            node.sfi = int(template_sfi) & 0x1F

        template_file_type = str(getattr(template, "file_type", "") or "").strip()
        # Map pySim shorthand ('TR', 'LF', 'CY', 'BT') onto runtime
        # labels. ``BT`` (BER-TLV) is not exercised by any cold-attach
        # EF but is mapped for completeness.
        structure_for_template = {
            "TR": "transparent",
            "LF": "linear-fixed",
            "CY": "cyclic",
            "BT": "ber-tlv",
        }.get(template_file_type, "")
        if (node.structure is None or len(node.structure) == 0) and len(structure_for_template) > 0:
            node.structure = structure_for_template

        if bool(getattr(template, "content_rqd", False)):
            continue

        has_data = len(bytes(node.data or b"")) > 0
        has_records = any(len(bytes(record or b"")) > 0 for record in node.records)
        if has_data or has_records:
            continue

        default_pattern = getattr(template, "default_val", None)
        if default_pattern is None or len(str(default_pattern)) == 0:
            continue

        if template_file_type == "TR":
            file_size = getattr(template, "file_size", None)
            if file_size is None or int(file_size) <= 0:
                continue
            payload = _expand_template_default(template, int(file_size))
            if len(payload) == 0:
                continue
            node.data = payload
            if structure_for_template:
                node.structure = structure_for_template
            continue

        if template_file_type in ("LF", "CY"):
            nb_rec = getattr(template, "nb_rec", None)
            rec_len = getattr(template, "rec_len", None)
            if nb_rec is None or rec_len is None:
                continue
            nb_rec_int = int(nb_rec)
            rec_len_int = int(rec_len)
            if nb_rec_int <= 0 or rec_len_int <= 0:
                continue
            record_bytes = _expand_template_default(template, rec_len_int)
            if len(record_bytes) == 0:
                continue
            node.records = [bytes(record_bytes) for _ in range(nb_rec_int)]
            if structure_for_template:
                node.structure = structure_for_template
            continue


def _apply_chv_table_from_profile(
    state: SimCardState,
    pin_entries: list[SimProfilePinEntry],
    puk_entries: list[SimProfilePukEntry],
) -> None:
    """Populate ``state.chv_references`` from a SAIP ``pinCodes`` /
    ``pukCodes`` set.

    Honours TS 102 221 §9.5.1 retry counter semantics: the SAIP
    encoding stores both max-attempts and remaining attempts in a
    single byte (high / low nibble). The ``pinAttributes`` byte's
    bit-0 toggles the "PIN enabled" state; SAIP §5.6.1 reserves the
    other bits for vendor flags so the simulator keeps them in
    ``SimChvReference`` only as the ``enabled`` flag.
    """
    if len(pin_entries) == 0 and len(puk_entries) == 0:
        return

    references: dict[int, SimChvReference] = {}
    for entry in pin_entries:
        pin_text = _decode_pin_value(entry.value)
        retry_limit = max(1, int(entry.max_attempts) & 0x0F)
        retries_remaining = max(0, min(retry_limit, int(entry.retries_remaining) & 0x0F))
        references[int(entry.key_reference) & 0xFF] = SimChvReference(
            reference=int(entry.key_reference) & 0xFF,
            value=pin_text,
            unblock_value="",
            enabled=(int(entry.attributes) & 0x01) != 0,
            verified=False,
            retry_limit=retry_limit,
            retries_remaining=retries_remaining,
            unblock_retry_limit=10,
            unblock_retries_remaining=10,
        )

    for entry in puk_entries:
        puk_text = _decode_pin_value(entry.value)
        max_attempts = max(1, min(10, int(entry.max_attempts) & 0xFF))
        retries_remaining = max(0, min(max_attempts, int(entry.retries_remaining) & 0xFF))
        target_reference = int(entry.key_reference) & 0xFF
        target = references.get(target_reference)
        if target is None:
            # PUKs without a matching PIN are still useful: VERIFY-PIN
            # might be issued before the SAIP-supplied PIN table, and
            # ETSI TS 102 221 §9 explicitly tolerates "PUK only"
            # bookkeeping for ADM keys.
            target = SimChvReference(
                reference=target_reference,
                value="",
                enabled=False,
                retry_limit=3,
                retries_remaining=3,
            )
            references[target_reference] = target
        target.unblock_value = puk_text
        target.unblock_retry_limit = max_attempts
        target.unblock_retries_remaining = retries_remaining

    state.chv_references = references


def _decode_pin_value(value: bytes) -> str:
    """Strip TS 102 221 §9.5.1 0xFF padding from an 8-byte PIN block.

    SAIP carries the PIN/PUK as ASCII left-aligned, padded with 0xFF.
    The simulator stores PINs as decimal strings so the toolkit / GP
    APIs can compare them directly.
    """
    body = bytes(value or b"")
    while len(body) > 0 and body[-1] == 0xFF:
        body = body[:-1]
    try:
        return body.decode("ascii")
    except UnicodeDecodeError:
        return body.hex().upper()


def _apply_security_domains_from_profile(
    state: SimCardState,
    domains: list[SimProfileSecurityDomain],
) -> None:
    """Reflect SAIP ``securityDomain`` PEs into the GP §11.4 registry.

    For the SD whose instance AID matches ``state.mno_sd_aid`` (the
    MNO-SD), this also populates ``state.scp03_keys`` from the SCP03
    baseline triplet (KVN ``0x01``). Per GP Card Spec v2.3.1 Amendment
    D §7.5 the KeyUsageQualifier byte selects the key role:

    - ENC: KUQ bit 5 (0x20 family) and key identifier 0x01.
    - MAC: KUQ bit 4 (0x10 family) and key identifier 0x02.
    - DEK: KUQ bit 7 (0x80 family) and key identifier 0x03.

    SDs with a non-MNO AID are still registered as ``SimGpAppEntry``
    rows so SELECT BY AID and GET STATUS find them, but their key
    material is intentionally not promoted to ``state.scp03_keys``
    until per-AID keysets are wired up.
    """
    if len(domains) == 0:
        return
    mno_aid_upper = str(state.mno_sd_aid or "").strip().upper()
    promoted_mno: bool = False
    for domain in domains:
        instance_aid = str(domain.instance_aid or "").strip().upper()
        if len(instance_aid) == 0:
            continue
        existing = next(
            (entry for entry in state.gp_apps if str(entry.aid).upper() == instance_aid),
            None,
        )
        privileges_bytes = bytes(domain.privileges or b"")
        if existing is None:
            state.gp_apps.append(
                SimGpAppEntry(
                    aid=instance_aid,
                    privileges=privileges_bytes,
                    lifecycle_state=int(domain.lifecycle_state) & 0xFF,
                    kind="sd",
                    associated_elf=str(domain.load_package_aid or "").strip().upper(),
                    modules=[],
                )
            )
        else:
            existing.privileges = privileges_bytes
            existing.lifecycle_state = int(domain.lifecycle_state) & 0xFF
            existing.kind = "sd"
            existing.associated_elf = str(domain.load_package_aid or "").strip().upper()
        # GP Card Spec v2.3.1 §11.1.2 reserves privilege byte 1 bit 8
        # (0x80) for "Security Domain". An SAIP profile typically
        # provisions a single SD instance (the MNO-SD); whichever SD
        # carries the SD privilege gets promoted to ``state.mno_sd_aid``
        # and its SCP03 baseline keys (KVN 0x01) are loaded into
        # ``state.scp03_keys``. If the profile contains multiple SDs,
        # the first match wins -- subsequent ones still appear in the
        # GP registry but do not override the active key material.
        is_security_domain = len(privileges_bytes) >= 1 and (privileges_bytes[0] & 0x80) != 0
        adopts_mno_role = (
            promoted_mno is False
            and (instance_aid == mno_aid_upper or len(mno_aid_upper) == 0 or is_security_domain)
        )
        if adopts_mno_role:
            state.mno_sd_aid = instance_aid
            _hydrate_mno_scp03_keys(state, domain)
            _hydrate_mno_scp80_keys(state, domain)
            promoted_mno = True


def _hydrate_mno_scp03_keys(state: SimCardState, domain: SimProfileSecurityDomain) -> None:
    """Promote a SAIP SD's baseline keyset into ``state.scp03_keys``.

    GP Card Spec v2.3.1 Amendment D §7.1.2 fixes the SCP03 baseline
    keyset to KeyIdentifier 0x01 = ENC, 0x02 = MAC, 0x03 = DEK. The
    KeyVersionNumber selects which baseline applies; SAIP profiles
    typically place the live triplet at KVN 0x01 ("default keyset")
    and any OTA / replacement keysets at KVN 0x40+ (e.g. SCP80 KICs
    and KIDs). We promote the lowest-KVN triplet that supplies all
    three keys so a profile that ships only SCP80 / SCP81 keys does
    not silently zero the SCP03 keyset.
    """
    candidates: dict[int, dict[int, bytes]] = {}
    for key_entry in domain.keys:
        key_version = int(key_entry.key_version) & 0xFF
        key_id = int(key_entry.key_identifier) & 0xFF
        if key_id not in (0x01, 0x02, 0x03):
            continue
        key_data = bytes(key_entry.key_data or b"")
        if len(key_data) == 0:
            continue
        candidates.setdefault(key_version, {})[key_id] = key_data
    selected_kvn = 0
    selected_keys: dict[int, bytes] = {}
    for key_version in sorted(candidates.keys()):
        triplet = candidates[key_version]
        if 0x01 in triplet and 0x02 in triplet and 0x03 in triplet:
            selected_kvn = key_version
            selected_keys = triplet
            break
    if len(selected_keys) == 3:
        state.scp03_keys.kenc = selected_keys[0x01]
        state.scp03_keys.kmac = selected_keys[0x02]
        state.scp03_keys.dek = selected_keys[0x03]
        state.scp03_keys.kvn = selected_kvn if selected_kvn != 0 else state.scp03_keys.kvn


def _hydrate_mno_scp80_keys(state: SimCardState, domain: SimProfileSecurityDomain) -> None:
    """Promote a SAIP SD's SCP80 OTA keyset into ``state.scp80_security``.

    GP Card Spec v2.3.1 Amendment B §B.4 reserves KeyVersionNumber
    range ``0x40..0x4F`` for SCP80 ("OTA Master") keysets, and TS 102
    225 §5.1 fixes the role of each key identifier inside the keyset:

    - KeyIdentifier ``0x01`` → KIc (cipher / encryption key).
    - KeyIdentifier ``0x02`` → KID (signature / integrity key).
    - KeyIdentifier ``0x03`` → KIK (key encryption / unwrapping key);
      optional, not modelled on the simulator yet.

    We promote the lowest-KVN pair that supplies both KIc and KID so
    a profile that ships only an OTA keyset (no SCP03 baseline) can
    still light up ``state.scp80_security``. The SPI / KIC / KID
    *format bytes* and TAR stay under ``isdr_config.json`` control --
    those are operator-deployment metadata that the SAIP profile
    does not encode in the ``securityDomain`` PE.
    """
    candidates: dict[int, dict[int, bytes]] = {}
    for key_entry in domain.keys:
        key_version = int(key_entry.key_version) & 0xFF
        if key_version < 0x40 or key_version > 0x4F:
            continue
        key_id = int(key_entry.key_identifier) & 0xFF
        if key_id not in (0x01, 0x02):
            continue
        key_data = bytes(key_entry.key_data or b"")
        if len(key_data) == 0:
            continue
        candidates.setdefault(key_version, {})[key_id] = key_data
    selected_keys: dict[int, bytes] = {}
    for key_version in sorted(candidates.keys()):
        pair = candidates[key_version]
        if 0x01 in pair and 0x02 in pair:
            selected_keys = pair
            break
    if len(selected_keys) == 2:
        state.scp80_security.key_enc = selected_keys[0x01]
        state.scp80_security.key_mac = selected_keys[0x02]


def _apply_rfm_instances_from_profile(
    state: SimCardState,
    rfm_entries: list[SimProfileRfmInstance],
) -> None:
    state.rfm_instances = list(rfm_entries)


def _apply_profile_apn_to_ipa_poll(
    state: SimCardState,
    nodes: dict[str, SimFileNode],
    path_index: dict[tuple[str, ...], str],
) -> None:
    """Project the SAIP-supplied APN onto ``state.toolkit.ipa_poll_apn``.

    The APN lives in EF.ACL (FID 6F57, transparent) per
    3GPP TS 31.102 §4.2.48: byte 0 is the APN count followed by N
    BER-TLVs with tag ``0xDD``, length, then ASCII APN bytes. The
    first APN wins. When the EF is missing or empty the helper
    preserves whatever the env / workspace fallback already placed
    in ``ipa_poll_apn``.
    """

    apn = _extract_apn_from_ef_acl(nodes, path_index)
    if len(apn) == 0:
        # Reset BPP override only if the previously active source was
        # itself a BPP override -- env / default sources persist.
        if str(getattr(state.toolkit, "ipa_poll_apn_source", "") or "") == "bpp":
            from SIMCARD.state import _resolve_default_ipa_poll_apn  # local to avoid cycles
            state.toolkit.ipa_poll_apn = _resolve_default_ipa_poll_apn()
            state.toolkit.ipa_poll_apn_source = "default"
        return
    state.toolkit.ipa_poll_apn = apn
    state.toolkit.ipa_poll_apn_source = "bpp"
    # Invalidate any previously cached resolved IP -- a new APN may
    # route to a different cellular context whose carrier-grade NAT
    # answers DNS differently.
    state.toolkit.ipa_poll_resolved_ip = ""
    state.toolkit.ipa_poll_resolved_ip_family = 0


def _extract_apn_from_ef_acl(
    nodes: dict[str, SimFileNode],
    path_index: dict[tuple[str, ...], str],
) -> str:
    """Return the first APN in EF.ACL (FID 6F57), or an empty string."""

    candidate_paths: list[tuple[str, ...]] = [
        ("MF", "ADF.USIM", "EF.ACL"),
        ("MF", "DF.GSM", "EF.ACL"),
        ("MF", "EF.ACL"),
    ]
    payload: bytes = b""
    for path in candidate_paths:
        node_id = path_index.get(path)
        if node_id is None:
            continue
        node = nodes.get(node_id)
        if node is None:
            continue
        data = bytes(getattr(node, "data", b"") or b"")
        if len(data) > 0:
            payload = data
            break
    if len(payload) == 0:
        # Fall back to a raw FID scan -- some profile images do not
        # name EF.ACL via the canonical (MF, ADF.USIM, EF.ACL) path.
        for node in nodes.values():
            fid = str(getattr(node, "fid", "") or "").upper()
            if fid == "6F57":
                data = bytes(getattr(node, "data", b"") or b"")
                if len(data) > 0:
                    payload = data
                    break
    if len(payload) < 2:
        return ""
    # Byte 0 is APN count (often 0x01 for single-APN profiles); the
    # remaining bytes are TLV-encoded.
    offset = 1
    if payload[offset] != 0xDD:
        return ""
    offset += 1
    if offset >= len(payload):
        return ""
    length = payload[offset]
    offset += 1
    if length == 0 or offset + length > len(payload):
        return ""
    apn_bytes = payload[offset : offset + length]
    return apn_bytes.decode("ascii", errors="ignore").strip()


def build_default_state() -> SimCardState:
    iccid = "89881111111111111112"
    # MCC/MNC 001/01 - 3GPP test PLMN. Keeps the default profile identity
    # compatible with osmo-hlr / open5gs / free5gc lab HSS configurations.
    imsi = "001010000000001"
    secondary_imsi = "001010000000002"
    mnc_length_default = 2
    primary_service_provider = "YggdraSIM Lab"
    secondary_service_provider = "YggdraSIM Lab (Secondary)"
    root_ci_pkid = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
    default_auth = SimProfileAuthConfig(
        algorithm="milenage",
        ki=bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC"),
        op=bytes.fromhex("CDC202D5123E20F62B6D676AC72CB318"),
        opc=bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF"),
        amf=bytes.fromhex("8000"),
        sqn=bytes.fromhex("000000000001"),
    )
    configured_data = SimEuiccConfiguredData(
        root_smds_address="lpa.ds.gsma.com",
        additional_root_smds_addresses=["smds2.yggdrasim.test", "smds3.yggdrasim.test"],
        allowed_ci_pkids=[root_ci_pkid],
        ci_list=[root_ci_pkid],
    )
    profiles = [
        SimProfileEntry(
            aid=ISDP1_AID,
            iccid=iccid,
            state="enabled",
            profile_class="operational",
            nickname="Lab (EU 01)",
            service_provider=primary_service_provider,
            profile_name="Yggdrasil Primary",
            imsi=imsi,
            impi="user@yggdrasim.test",
            notification_address="rsp.example.com",
            profile_image=_default_profile_image(
                iccid,
                imsi,
                "user@yggdrasim.test",
                service_provider=primary_service_provider,
                mnc_length=mnc_length_default,
            ),
            profile_source="json",
            auth_config=copy.deepcopy(default_auth),
        ),
        SimProfileEntry(
            aid=ISDP2_AID,
            iccid="89881111111111111129",
            state="disabled",
            profile_class="test",
            nickname="Lab (EU 02)",
            service_provider=secondary_service_provider,
            profile_name="Yggdrasil Secondary",
            imsi=secondary_imsi,
            impi="user-secondary@yggdrasim.test",
            notification_address="rsp.example.com",
            profile_image=_default_profile_image(
                "89881111111111111129",
                secondary_imsi,
                "user-secondary@yggdrasim.test",
                service_provider=secondary_service_provider,
                mnc_length=mnc_length_default,
            ),
            profile_source="json",
            auth_config=copy.deepcopy(default_auth),
        ),
    ]
    state = SimCardState(
        atr=DEFAULT_SIM_ATR,
        eid="89045967676472615349763031303005",
        iccid=iccid,
        imsi=imsi,
        default_dp_address="rsp.example.com",
        root_ci_pkid=root_ci_pkid,
        isdr_aid=ISDR_AID,
        isdr_label="ISDR",
        ecasd_aid=ECASD_AID,
        ecasd_label="ECASD",
        mno_sd_aid=MNO_SD_AID,
        mno_sd_label="MNO-SD",
        configured_data=configured_data,
        eim_entries=[
            SimEimEntry(
                eim_id="2.25.311782205282738360923618091971140414400",
                eim_fqdn="eim.yggdrasim.example.test",
                eim_id_type=1,
                counter_value=1,
                association_token=16,
                supported_protocol_bits=[0, 2],
                euicc_ci_pkid=root_ci_pkid,
                indirect_profile_download=True,
            )
        ],
        profiles=profiles,
        active_profile_aid=profiles[0].aid,
        chv_references={
            0x01: SimChvReference(reference=0x01, value="1234", unblock_value="12345678"),
            0x81: SimChvReference(reference=0x81, value="1234", unblock_value="12345678"),
        },
    )
    state.toolkit.menu_title = "YggdraSIM"
    nodes: dict[str, SimFileNode] = {}
    _register_node(nodes, SimFileNode(node_id="3F00", name="MF", kind="mf", fid="3F00"))
    _register_node(
        nodes,
        SimFileNode(
            node_id="ISDR",
            name="ISD-R",
            kind="adf",
            aid=state.isdr_aid,
            label=state.isdr_label,
            parent_id="3F00",
        ),
    )
    _register_node(
        nodes,
        SimFileNode(
            node_id="ECASD",
            name="ECASD",
            kind="adf",
            aid=state.ecasd_aid,
            label=state.ecasd_label,
            parent_id="3F00",
        ),
    )
    _register_node(
        nodes,
        SimFileNode(
            node_id="MNO_SD",
            name="MNO-SD",
            kind="adf",
            aid=state.mno_sd_aid,
            label=state.mno_sd_label,
            parent_id="3F00",
        ),
    )
    state.base_nodes = copy.deepcopy(nodes)
    state.nodes = copy.deepcopy(nodes)
    rebuild_runtime_filesystem(state)
    return state


class EtsiFileSystem:
    def __init__(self, state: SimCardState) -> None:
        self.state = state

    def reset(self) -> None:
        self.state.current_node_id = "3F00"

    def current_node(self) -> SimFileNode:
        return self.state.nodes[self.state.current_node_id]

    def _find_child_by_fid(self, parent_id: str, fid: str) -> SimFileNode | None:
        parent = self.state.nodes.get(parent_id)
        if parent is None:
            return None
        target = fid.upper()
        for child_id in parent.children:
            child = self.state.nodes[child_id]
            if child.fid.upper() == target:
                return child
        return None

    def _find_node_by_fid(self, fid: str) -> SimFileNode | None:
        """Global FID lookup. Reserved for AID-resolution and snapshot paths.

        The terminal-facing default-scope SELECT (P1=0x00) goes through
        ``_find_node_by_fid_default_scope`` so the simulator no longer
        accepts ``SELECT 6F07`` from MF context, in line with ETSI
        TS 102 221 §8.4.2.
        """
        target = fid.upper()
        for node in self.state.nodes.values():
            if node.fid.upper() == target:
                return node
        return None

    def _enclosing_adf(self, node_id: str) -> "SimFileNode | None":
        cursor_id = str(node_id or "").strip()
        while len(cursor_id) > 0:
            node = self.state.nodes.get(cursor_id)
            if node is None:
                return None
            if str(getattr(node, "kind", "") or "").strip().lower() == "adf":
                return node
            cursor_id = str(getattr(node, "parent_id", "") or "").strip()
        return None

    def _find_node_by_fid_default_scope(self, fid: str) -> "SimFileNode | None":
        """ETSI TS 102 221 §8.4.2 default-scope FID resolver.

        Search order, stopping at the first match:

        1. Current DF (matches itself if the FID is its own).
        2. Direct children of the current DF.
        3. If the current node is an EF, the parent DF and its
           children (i.e. siblings of the current EF).
        4. The grandparent DF and its children (siblings of the
           current DF) when the current node is a DF/ADF.
        5. The currently selected ADF (if the cursor is anywhere
           inside an ADF subtree) and its direct children.

        A global tree walk is intentionally NOT performed: a real
        UICC cannot resolve a USIM-scoped EF from MF context.
        """
        target = str(fid or "").strip().upper()
        if len(target) == 0:
            return None
        current = self.state.nodes.get(self.state.current_node_id)
        if current is None:
            return None

        if current.fid.upper() == target:
            return current

        # Anchor: if currently on an EF, scope is the parent DF.
        anchor_id = self.state.current_node_id
        if str(getattr(current, "kind", "") or "").strip().lower() == "ef":
            anchor_id = str(getattr(current, "parent_id", "") or "").strip() or anchor_id

        anchor = self.state.nodes.get(anchor_id)
        if anchor is not None and anchor.fid.upper() == target:
            return anchor

        candidate = self._find_child_by_fid(anchor_id, target)
        if candidate is not None:
            return candidate

        if anchor is not None:
            grandparent_id = str(getattr(anchor, "parent_id", "") or "").strip()
            if len(grandparent_id) > 0:
                grandparent = self.state.nodes.get(grandparent_id)
                if grandparent is not None and grandparent.fid.upper() == target:
                    return grandparent
                sibling = self._find_child_by_fid(grandparent_id, target)
                if sibling is not None:
                    return sibling

        adf = self._enclosing_adf(self.state.current_node_id)
        if adf is not None:
            if adf.fid.upper() == target:
                return adf
            adf_child = self._find_child_by_fid(adf.node_id, target)
            if adf_child is not None:
                return adf_child

        return None

    def _find_node_by_aid(self, aid_hex: str) -> SimFileNode | None:
        target = aid_hex.upper()
        for node in self.state.nodes.values():
            if node.aid.upper() == target:
                return node
        return None

    def select(self, selector: bytes, p1: int = 0x00, p2: int = 0x00) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.1 SELECT.

        P1 encodes the selection scope (FID, AID, parent DF, path from MF,
        path from current DF). P2 bits b4-b3 would gate FCP return under a
        strict reading of ETSI TS 102 221 Table 11.2, but UICCs accessed
        through OTA/SCP80 commonly issue SELECT with P2='0C' and still
        surface the FCP; the simulator follows that interop profile.
        """
        p1_value = int(p1) & 0xFF
        normalized = bytes(selector or b"")

        node = self._resolve_select_target(p1_value, normalized)
        if node is None:
            return b"", 0x6A, 0x82
        self.state.current_node_id = node.node_id
        return self.build_fcp(node), 0x90, 0x00

    def _resolve_select_target(self, p1: int, selector: bytes) -> SimFileNode | None:
        selector_hex = selector.hex().upper()

        if p1 == 0x00:
            if len(selector) == 2:
                return self._find_node_by_fid_default_scope(selector_hex)
            return self._find_node_by_aid(selector_hex)

        if p1 == 0x01:
            if len(selector) != 2:
                return None
            return self._find_child_by_fid(self.state.current_node_id, selector_hex)

        if p1 == 0x02:
            if len(selector) != 2:
                return None
            candidate = self._find_child_by_fid(self.state.current_node_id, selector_hex)
            if candidate is None or candidate.kind != "ef":
                return None
            return candidate

        if p1 == 0x03:
            current = self.state.nodes.get(self.state.current_node_id)
            if current is None:
                return None
            parent_id = str(getattr(current, "parent_id", "") or "").strip()
            if len(parent_id) == 0:
                return None
            return self.state.nodes.get(parent_id)

        if p1 == 0x04:
            return self._find_node_by_aid_prefix(selector_hex)

        if p1 == 0x08:
            return self._resolve_select_by_path(selector, anchor_mf=True)

        if p1 == 0x09:
            return self._resolve_select_by_path(selector, anchor_mf=False)

        return None

    def _find_node_by_aid_prefix(self, aid_hex: str) -> SimFileNode | None:
        target = aid_hex.upper()
        if len(target) == 0:
            return None
        exact = self._find_node_by_aid(target)
        if exact is not None:
            return exact
        for node in self.state.nodes.values():
            aid_candidate = str(getattr(node, "aid", "") or "").strip().upper()
            if len(aid_candidate) == 0:
                continue
            if aid_candidate.startswith(target):
                return node
        return None

    def _resolve_select_by_path(self, selector: bytes, *, anchor_mf: bool) -> SimFileNode | None:
        raw = bytes(selector or b"")
        if len(raw) == 0 or len(raw) % 2 != 0:
            return None
        fids = [raw[index : index + 2].hex().upper() for index in range(0, len(raw), 2)]

        if anchor_mf:
            mf_node = self.state.nodes.get("3F00")
            if mf_node is None:
                return None
            current = mf_node
            if fids[0] == "3F00":
                fids = fids[1:]
        else:
            current = self.state.nodes.get(self.state.current_node_id)
            if current is None:
                return None

        for fid in fids:
            if fid == current.fid.upper():
                continue
            candidate = self._find_child_by_fid(current.node_id, fid)
            if candidate is None:
                return None
            current = candidate
        return current

    def read_binary(
        self,
        *,
        p1: int = 0x00,
        p2: int = 0x00,
        offset: int | None = None,
        le: int | None = None,
    ) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.3 READ BINARY.

        If P1 bit 8 is set the lower 5 bits of P1 select an EF by SFI
        under the currently selected DF and P2 is the byte offset
        (0..255). Otherwise P1||P2 is a 15-bit offset into the currently
        selected transparent EF.
        """
        p1_value = int(p1) & 0xFF
        p2_value = int(p2) & 0xFF
        if offset is not None:
            target_node = self.current_node()
            resolved_offset = int(offset)
        elif p1_value & 0x80:
            sfi = p1_value & 0x1F
            target_node = self._resolve_sfi_under_current(sfi)
            if target_node is None:
                return b"", 0x6A, 0x82
            self.state.current_node_id = target_node.node_id
            resolved_offset = p2_value
        else:
            target_node = self.current_node()
            resolved_offset = ((p1_value & 0x7F) << 8) | p2_value

        if target_node.kind != "ef" or target_node.structure != "transparent":
            # ETSI TS 102 221 §11.1.3: READ BINARY against a record-oriented
            # or non-EF target is reported as "command incompatible with
            # file structure" (69 81), not "no current EF" (69 86).
            return b"", 0x69, 0x81
        # TS 102 221 §11.1.13: a deactivated EF reports "selected file
        # invalidated" on every data-bearing access. SELECT itself is
        # allowed (the FCP signals the lifecycle so the terminal can
        # ACTIVATE the file again) but READ/UPDATE/SEARCH are blocked.
        if (int(target_node.lifecycle_state) & 0xFF) != 0x05:
            return b"", 0x62, 0x83
        if resolved_offset < 0 or resolved_offset > len(target_node.data):
            return b"", 0x6B, 0x00
        payload = target_node.data[resolved_offset:]
        if le not in (None, 0, 256, 65536):
            payload = payload[:le]
        return payload, 0x90, 0x00

    def read_record(
        self,
        record_number: int,
        *,
        p2: int = 0x04,
        le: int | None = None,
    ) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.5 READ RECORD.

        P2 bits 7..3 hold the SFI (0 means current EF). P2 bits 2..0
        hold the mode:

        - ``0x02`` Next record (linear-fixed and cyclic).
        - ``0x03`` Previous record (linear-fixed and cyclic).
        - ``0x04`` Absolute. On linear-fixed P1 is the record id; on
          cyclic P1 = 0 means the current (most-recent) record.

        Cyclic EFs keep the most-recent record at index
        0 of ``records``; ``record_number = 1`` returns that
        record. Absolute reads with P1 in range 1..record_count map
        directly into the slot history (1 = most recent, 2 = next
        oldest, ...).
        """
        p2_value = int(p2) & 0xFF
        sfi = (p2_value >> 3) & 0x1F
        mode = p2_value & 0x07

        if sfi != 0:
            target_node = self._resolve_sfi_under_current(sfi)
            if target_node is None:
                return b"", 0x6A, 0x82
            self.state.current_node_id = target_node.node_id
        else:
            target_node = self.current_node()

        if target_node.kind != "ef" or target_node.structure not in (
            "linear-fixed",
            "cyclic",
        ):
            # ETSI TS 102 221 §11.1.5: READ RECORD against a transparent
            # EF is reported as "command incompatible with file
            # structure" (69 81).
            return b"", 0x69, 0x81
        if (int(target_node.lifecycle_state) & 0xFF) != 0x05:
            return b"", 0x62, 0x83

        record_count = len(target_node.records)
        if record_count == 0:
            return b"", 0x6A, 0x83

        if mode in (0x02, 0x06):
            selected_record = max(1, int(record_number or 0))
        elif mode in (0x03, 0x07):
            selected_record = max(1, int(record_number or 0))
        else:
            selected_record = int(record_number or 0)
            if selected_record == 0 and target_node.structure == "cyclic":
                # TS 102 221 §11.1.5 Table 11.16: P1 = 0 with mode
                # 0x04 on a cyclic EF means "current record" -- the
                # most-recently written one.
                selected_record = 1

        if selected_record <= 0 or selected_record > record_count:
            return b"", 0x6A, 0x83
        payload = target_node.records[selected_record - 1]
        if le not in (None, 0, 256, 65536):
            payload = payload[:le]
        return payload, 0x90, 0x00

    def _resolve_sfi_under_current(self, sfi: int) -> SimFileNode | None:
        """ETSI TS 102 221 §11.1.3.4 SFI resolution.

        The SFI is interpreted "in the currently selected DF". When
        the current node is itself an EF (because the previous APDU
        was a READ BINARY/RECORD by SFI), the search has to walk up
        to that EF's parent DF; otherwise the lookup would always
        return ``6A 82`` after the first SFI-style access.
        """
        sfi_value = int(sfi) & 0x1F
        if sfi_value == 0:
            return None
        anchor = self.state.nodes.get(self.state.current_node_id)
        if anchor is None:
            return None
        if anchor.kind == "ef":
            anchor = self.state.nodes.get(anchor.parent_id)
            if anchor is None:
                return None
        for child_id in anchor.children:
            child = self.state.nodes.get(child_id)
            if child is None:
                continue
            if child.kind != "ef":
                continue
            child_sfi = getattr(child, "sfi", None)
            if child_sfi is None:
                continue
            if (int(child_sfi) & 0x1F) == sfi_value:
                return child
        return None

    def update_binary(
        self,
        *,
        p1: int = 0x00,
        p2: int = 0x00,
        payload: bytes = b"",
        offset: int | None = None,
    ) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.4 UPDATE BINARY.

        Mirrors the SFI/offset handling of READ BINARY (§11.1.3). If
        P1 bit 8 is set the lower 5 bits select an EF by SFI under the
        currently selected DF and P2 is the byte offset (0..255).
        Otherwise P1||P2 encodes a 15-bit offset into the current
        transparent EF. ``offset`` is honoured for backwards
        compatibility with callers that pre-decode the location.
        """
        p1_value = int(p1) & 0xFF
        p2_value = int(p2) & 0xFF
        if offset is not None:
            target_node = self.current_node()
            resolved_offset = int(offset)
        elif p1_value & 0x80:
            sfi = p1_value & 0x1F
            target_node = self._resolve_sfi_under_current(sfi)
            if target_node is None:
                return b"", 0x6A, 0x82
            self.state.current_node_id = target_node.node_id
            resolved_offset = p2_value
        else:
            target_node = self.current_node()
            resolved_offset = ((p1_value & 0x7F) << 8) | p2_value

        if target_node.kind != "ef" or target_node.structure != "transparent":
            return b"", 0x69, 0x81
        if (int(target_node.lifecycle_state) & 0xFF) != 0x05:
            return b"", 0x62, 0x83
        if self._check_write_access(target_node) is False:
            return b"", 0x69, 0x82
        existing = bytearray(target_node.data)
        if resolved_offset > len(existing):
            existing.extend(b"\xFF" * (resolved_offset - len(existing)))
        end_offset = resolved_offset + len(payload)
        if end_offset > len(existing):
            existing.extend(b"\xFF" * (end_offset - len(existing)))
        existing[resolved_offset:end_offset] = payload
        target_node.data = bytes(existing)
        self._persist_node_to_active_image(target_node)
        return b"", 0x90, 0x00

    def update_record(
        self,
        record_number: int,
        payload: bytes,
        *,
        p2: int = 0x04,
    ) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.6 UPDATE RECORD.

        P2 bits 7..3 hold the SFI (0 = current EF). P2 bits 2..0
        hold the access mode:

        - ``0x04`` Absolute -- linear-fixed only. P1 is the record
          number to overwrite.
        - ``0x03`` Previous -- cyclic only. The card
          overwrites what was the OLDEST record, then rotates the
          ring so the new record becomes the most-recent (index 0).
          P1 is ignored per spec.

        Other modes return ``69 81`` ("command incompatible with
        file structure") to mirror commercial UICC behaviour.
        """
        p2_value = int(p2) & 0xFF
        sfi = (p2_value >> 3) & 0x1F
        mode = p2_value & 0x07
        if sfi != 0:
            target_node = self._resolve_sfi_under_current(sfi)
            if target_node is None:
                return b"", 0x6A, 0x82
            self.state.current_node_id = target_node.node_id
        else:
            target_node = self.current_node()
        if target_node.kind != "ef" or target_node.structure not in (
            "linear-fixed",
            "cyclic",
        ):
            return b"", 0x69, 0x81
        if (int(target_node.lifecycle_state) & 0xFF) != 0x05:
            return b"", 0x62, 0x83
        if self._check_write_access(target_node) is False:
            return b"", 0x69, 0x82
        if target_node.structure == "cyclic":
            if mode != 0x03:
                # TS 102 221 §11.1.6: UPDATE RECORD on a cyclic EF
                # only accepts mode 0x03 (PREVIOUS). Other modes
                # are rejected with "command incompatible with file
                # structure".
                return b"", 0x69, 0x81
            if len(target_node.records) == 0:
                return b"", 0x6A, 0x83
            fill_length = target_node.record_length or len(payload)
            new_record = bytes(payload)
            if fill_length > 0 and len(new_record) < fill_length:
                new_record = new_record + b"\xFF" * (fill_length - len(new_record))
            # Drop the oldest slot, prepend the new record so it
            # becomes index 0 (the "most-recent" entry that READ
            # RECORD with P1=0 will return).
            target_node.records.pop()
            target_node.records.insert(0, new_record)
            self._persist_node_to_active_image(target_node)
            return b"", 0x90, 0x00
        if record_number <= 0:
            return b"", 0x6A, 0x83
        while len(target_node.records) < record_number:
            fill_length = target_node.record_length or len(payload)
            target_node.records.append(b"\xFF" * fill_length)
        target_node.records[record_number - 1] = bytes(payload)
        self._persist_node_to_active_image(target_node)
        return b"", 0x90, 0x00

    def deactivate_file(self) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.13 DEACTIVATE FILE.

        Operates on the currently selected EF/DF and flips its
        lifecycle byte from 0x05 to 0x04. Subsequent READ/UPDATE
        operations against the file return ``62 83`` (selected file
        invalidated) until ACTIVATE FILE is issued. The lifecycle
        change is persisted into the active profile image so a
        restart preserves the deactivated state, mirroring how a
        commercial UICC retains the lifecycle byte across resets.
        """
        node = self.current_node()
        if node.kind not in ("ef", "df", "adf", "mf"):
            return b"", 0x69, 0x81
        if node.kind == "mf":
            # The MF cannot be deactivated. TS 102 221 §11.1.13 lists
            # the operation as applicable to "the EF or DF currently
            # selected"; deactivating MF would brick the card.
            return b"", 0x69, 0x86
        if (int(node.lifecycle_state) & 0xFF) == 0x04:
            return b"", 0x90, 0x00
        node.lifecycle_state = 0x04
        self._persist_node_to_active_image(node)
        return b"", 0x90, 0x00

    def activate_file(self) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.14 ACTIVATE FILE.

        A terminated file (lifecycle 0x0C) cannot be re-activated --
        TERMINATE EF/DF is irreversible by design. Real cards return
        ``69 85`` for the request. Already-activated files succeed
        idempotently to match commercial UICC behaviour.
        """
        node = self.current_node()
        if node.kind not in ("ef", "df", "adf", "mf"):
            return b"", 0x69, 0x81
        current = int(node.lifecycle_state) & 0xFF
        if current == 0x0C:
            return b"", 0x69, 0x85
        if current == 0x05:
            return b"", 0x90, 0x00
        node.lifecycle_state = 0x05
        self._persist_node_to_active_image(node)
        return b"", 0x90, 0x00

    def terminate_ef(self) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.16 TERMINATE EF.

        Flips the currently selected EF's lifecycle byte to 0x0C
        (terminated). The change is irreversible: ACTIVATE FILE
        on the same node afterwards is rejected with ``69 85``.
        Already-terminated nodes succeed idempotently.
        """
        node = self.current_node()
        if node.kind != "ef":
            return b"", 0x69, 0x81
        if (int(node.lifecycle_state) & 0xFF) == 0x0C:
            return b"", 0x90, 0x00
        node.lifecycle_state = 0x0C
        self._persist_node_to_active_image(node)
        return b"", 0x90, 0x00

    def terminate_df(self) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.17 TERMINATE DF.

        Same semantics as TERMINATE EF, but limited to DF/ADF
        nodes. The MF cannot be terminated (use TERMINATE CARD
        USAGE for that) -- attempting it returns ``69 86``.
        """
        node = self.current_node()
        if node.kind not in ("df", "adf"):
            if node.kind == "mf":
                return b"", 0x69, 0x86
            return b"", 0x69, 0x81
        if (int(node.lifecycle_state) & 0xFF) == 0x0C:
            return b"", 0x90, 0x00
        node.lifecycle_state = 0x0C
        self._persist_node_to_active_image(node)
        return b"", 0x90, 0x00

    def create_file(self, payload: bytes) -> tuple[bytes, int, int]:
        """ETSI TS 102 222 §6.3 CREATE FILE.

        Parses an FCP TLV (root tag ``62``) carried in the C-APDU
        body and creates a new EF as a child of the currently
        selected DF. The simulator implements the spec's most
        common subset: transparent EFs (file descriptor byte
        ``0x01``) and linear-fixed EFs (``0x02``); cyclic EFs are
        also accepted (``0x06``). Recognised FCP children:

        - ``80`` File Size (transparent EF) or record length helper.
        - ``81`` Total File Size (optional).
        - ``82`` File Descriptor: byte 0 is the file type / structure,
          byte 1 + 2 are 0x21 (UICC), bytes 3..4 (record EFs only)
          are the record length, byte 5 (record EFs only) is the
          number of records.
        - ``83`` File ID (2 bytes, big-endian).
        - ``8A`` Lifecycle State (defaults to ``0x05`` operational).

        Common diagnostics:

        - ``6A 80`` -- malformed FCP / missing mandatory tag.
        - ``6A 84`` -- not enough memory (we cap synthetic EFs at
          64 KiB to keep the in-memory tree bounded).
        - ``6A 89`` -- file already exists in the target DF.
        - ``69 86`` -- target DF is the MF or an ADF and the file
          structure is unsupported by that scope.
        - ``69 85`` -- current selection is not a DF.
        """
        body = bytes(payload or b"")
        if len(body) < 2 or body[0] != 0x62:
            return b"", 0x6A, 0x80
        fcp_offset, fcp_length = self._read_ber_length(body, 1)
        if fcp_offset is None or fcp_offset + fcp_length > len(body):
            return b"", 0x6A, 0x80
        fcp_body = body[fcp_offset : fcp_offset + fcp_length]
        children = self._parse_tlv_children(fcp_body)
        if children is None:
            return b"", 0x6A, 0x80
        descriptor = children.get(0x82)
        fid_bytes = children.get(0x83)
        size_bytes = children.get(0x80)
        lifecycle_bytes = children.get(0x8A)
        if descriptor is None or fid_bytes is None or len(fid_bytes) != 2:
            return b"", 0x6A, 0x80
        if len(descriptor) < 1:
            return b"", 0x6A, 0x80
        descriptor_byte = descriptor[0] & 0xFF
        # TS 102 221 §11.1.1.4.3 Table 11.5 file-descriptor bytes:
        # 0x01 working EF transparent, 0x02 working EF linear-fixed,
        # 0x06 working EF cyclic.
        structure = ""
        if descriptor_byte == 0x01:
            structure = "transparent"
        elif descriptor_byte == 0x02:
            structure = "linear-fixed"
        elif descriptor_byte == 0x06:
            structure = "cyclic"
        else:
            return b"", 0x6A, 0x80
        parent = self.current_node()
        if parent.kind not in ("df", "adf", "mf"):
            return b"", 0x69, 0x85
        fid_hex = fid_bytes.hex().upper()
        if self._find_child_by_fid(parent.node_id, fid_hex) is not None:
            return b"", 0x6A, 0x89
        # Resolve size. Transparent EFs use tag 80 directly; record
        # EFs encode (record_length, record_count) inside the file
        # descriptor (bytes 3..5) per §11.1.1.4.3.
        record_length = 0
        record_count = 0
        if structure in ("linear-fixed", "cyclic"):
            if len(descriptor) < 5:
                return b"", 0x6A, 0x80
            record_length = int.from_bytes(descriptor[3:5], "big")
            record_count = int(descriptor[5]) if len(descriptor) >= 6 else 0
            if record_count == 0 and size_bytes is not None and record_length > 0:
                record_count = int.from_bytes(size_bytes, "big") // record_length
            if record_length == 0 or record_count == 0:
                return b"", 0x6A, 0x80
            total_bytes = record_length * record_count
        else:
            if size_bytes is None:
                return b"", 0x6A, 0x80
            total_bytes = int.from_bytes(size_bytes, "big")
        # 64 KiB synthetic ceiling: large EFs are rare in real OTA
        # scripts and a runaway value would inflate the in-memory
        # tree without bound. Real cards reply 6A 84 when free
        # memory is exhausted; we emulate that boundary explicitly.
        if total_bytes <= 0 or total_bytes > 0x10000:
            return b"", 0x6A, 0x84
        new_node = SimFileNode(
            node_id=fid_hex,
            name=f"EF_{fid_hex}",
            kind="ef",
            fid=fid_hex,
            parent_id=parent.node_id,
            structure=structure,
            data=b"\xFF" * total_bytes if structure == "transparent" else b"",
            records=[
                b"\xFF" * record_length for _ in range(record_count)
            ] if structure != "transparent" else [],
            lifecycle_state=int(lifecycle_bytes[0]) if lifecycle_bytes else 0x05,
        )
        # Honour FID collisions across the whole tree by suffixing
        # the parent path -- the simulator keys nodes by node_id
        # which must be unique even if the FID itself is reused
        # under a different DF. The TS 102 222 spec does not
        # prescribe the internal key, only that SELECT FID resolves
        # within scope.
        if new_node.node_id in self.state.nodes:
            new_node.node_id = f"{parent.node_id}_{fid_hex}"
        self.state.nodes[new_node.node_id] = new_node
        parent.children.append(new_node.node_id)
        return b"", 0x90, 0x00

    def delete_file(self, p1: int, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        """ETSI TS 102 222 §6.5 DELETE FILE.

        Removes the EF or DF identified by the FID carried in TLV
        ``83`` of the C-APDU body. When the body is empty the
        currently selected EF / DF is targeted (matching the
        commercial-card "implicit" form). Deleting a DF cascades
        through every child node so the runtime tree never holds
        an orphaned EF after the operation.

        P1 / P2 are reserved per §6.5.2 and ignored; the simulator
        retains the parameters in the signature for future
        extensions (e.g. a "purge data only" variant).

        Status words follow §6.5.3:

        - ``6A 80`` -- malformed body or zero-length FID.
        - ``6A 82`` -- target FID does not resolve under the
          current scope.
        - ``69 86`` -- MF cannot be deleted.
        - ``62 83`` -- target file is already terminated
          (lifecycle ``0x0C`` / ``0x04``); deletion is permitted
          only on operational files in this simulator to mirror
          commercial-card behaviour.
        """
        del p1
        del p2
        body = bytes(payload or b"")
        target: SimFileNode | None = None
        if len(body) > 0:
            children = self._parse_tlv_children(body)
            if children is None:
                return b"", 0x6A, 0x80
            fid_bytes = children.get(0x83)
            if fid_bytes is None or len(fid_bytes) != 2:
                return b"", 0x6A, 0x80
            target = self._find_child_by_fid(
                self.current_node().node_id,
                fid_bytes.hex().upper(),
            )
            if target is None:
                target = self._find_node_by_fid(fid_bytes.hex().upper())
        if target is None:
            target = self.current_node()
        if target.kind == "mf":
            return b"", 0x69, 0x86
        if (int(target.lifecycle_state) & 0xFF) != 0x05:
            return b"", 0x62, 0x83
        # Recursively gather descendants so a DELETE on a DF leaves
        # the tree consistent. We collect node_ids first to avoid
        # mutating the dict while iterating it.
        to_remove: list[str] = []

        def collect(node_id: str) -> None:
            node = self.state.nodes.get(node_id)
            if node is None:
                return
            for child_id in list(node.children):
                collect(child_id)
            to_remove.append(node_id)

        collect(target.node_id)
        parent_id = str(getattr(target, "parent_id", "") or "").strip()
        for node_id in to_remove:
            self.state.nodes.pop(node_id, None)
        parent = self.state.nodes.get(parent_id)
        if parent is not None and target.node_id in parent.children:
            parent.children = [
                child for child in parent.children if child != target.node_id
            ]
        if self.state.current_node_id in to_remove:
            self.state.current_node_id = parent_id or "3F00"
        return b"", 0x90, 0x00

    def resize_file(self, p1: int, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        """ETSI TS 102 222 §6.4 RESIZE FILE.

        Targets the EF identified by the FID in the C-APDU body
        (or the currently selected EF when the body is empty). The
        new size is encoded in TLV ``80`` (file size). For
        transparent EFs the data buffer is truncated or padded with
        ``0xFF`` to the new length; for record EFs the count of
        records is adjusted (records added at the end are
        ``0xFF``-filled; surplus records are dropped). P1 and P2
        are reserved per §6.4.2 and currently ignored to mirror
        commercial-card tolerance for vendor extensions.
        """
        del p1
        del p2
        body = bytes(payload or b"")
        if len(body) == 0:
            return b"", 0x6A, 0x80
        children = self._parse_tlv_children(body)
        if children is None:
            return b"", 0x6A, 0x80
        size_bytes = children.get(0x80)
        if size_bytes is None or len(size_bytes) == 0:
            return b"", 0x6A, 0x80
        new_size = int.from_bytes(size_bytes, "big")
        if new_size <= 0 or new_size > 0x10000:
            return b"", 0x6A, 0x84
        target_fid = children.get(0x83)
        node: SimFileNode | None = None
        if target_fid is not None and len(target_fid) == 2:
            node = self._find_child_by_fid(
                self.current_node().node_id,
                target_fid.hex().upper(),
            )
        if node is None:
            node = self.current_node()
        if node.kind != "ef":
            return b"", 0x69, 0x81
        if (int(node.lifecycle_state) & 0xFF) != 0x05:
            return b"", 0x62, 0x83
        if node.structure == "transparent":
            current = bytearray(node.data)
            if new_size < len(current):
                node.data = bytes(current[:new_size])
            else:
                current.extend(b"\xFF" * (new_size - len(current)))
                node.data = bytes(current)
        elif node.structure in ("linear-fixed", "cyclic"):
            record_length = node.record_length or new_size
            if record_length == 0 or new_size % record_length != 0:
                return b"", 0x6A, 0x80
            target_count = new_size // record_length
            while len(node.records) < target_count:
                node.records.append(b"\xFF" * record_length)
            if len(node.records) > target_count:
                node.records = node.records[:target_count]
        else:
            return b"", 0x69, 0x81
        self._persist_node_to_active_image(node)
        return b"", 0x90, 0x00

    @staticmethod
    def _read_ber_length(body: bytes, offset: int) -> tuple[int | None, int]:
        if offset >= len(body):
            return None, 0
        first = body[offset] & 0xFF
        if first < 0x80:
            return offset + 1, first
        n = first & 0x7F
        if n == 0 or offset + 1 + n > len(body):
            return None, 0
        length = int.from_bytes(body[offset + 1 : offset + 1 + n], "big")
        return offset + 1 + n, length

    def _parse_tlv_children(self, body: bytes) -> dict[int, bytes] | None:
        """Walk a flat sequence of primitive BER TLVs and return a
        ``tag -> value`` dictionary. Returns ``None`` on a malformed
        length encoding so the caller can reject the request with
        ``6A 80``. Constructed tags (the 0x20 bit set) are stored
        verbatim too because some FCP children re-use them.
        """
        out: dict[int, bytes] = {}
        offset = 0
        while offset < len(body):
            tag = body[offset] & 0xFF
            length_offset, length = self._read_ber_length(body, offset + 1)
            if length_offset is None or length_offset + length > len(body):
                return None
            out[tag] = body[length_offset : length_offset + length]
            offset = length_offset + length
        return out

    def increase(self, payload: bytes) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.8 INCREASE.

        Only valid on cyclic EFs. The most recent record is treated
        as an unsigned big-endian integer; the request body is
        likewise interpreted as the increment value (1-3 bytes is
        the spec norm). The result is a new most-recent record
        carrying the new value, and the response carries the new
        value followed by the increase value, both padded to the
        record length per §11.1.8.4.

        Errors:

        - Non-cyclic / non-EF target -- ``69 81``.
        - Empty body -- ``67 00`` (Lc inconsistent).
        - Increment overflows the record width -- ``63 00``.
        - File deactivated / terminated -- ``62 83``.
        """
        node = self.current_node()
        if node.kind != "ef" or node.structure != "cyclic":
            return b"", 0x69, 0x81
        if (int(node.lifecycle_state) & 0xFF) != 0x05:
            return b"", 0x62, 0x83
        body = bytes(payload or b"")
        if len(body) == 0:
            return b"", 0x67, 0x00
        if self._check_write_access(node) is False:
            return b"", 0x69, 0x82
        record_length = node.record_length
        if record_length == 0:
            return b"", 0x69, 0x81
        if len(body) > record_length:
            return b"", 0x67, 0x00
        last_record = node.records[-1] if len(node.records) > 0 else b"\x00" * record_length
        current_value = int.from_bytes(last_record, "big", signed=False)
        increment_value = int.from_bytes(body, "big", signed=False)
        new_value = current_value + increment_value
        if new_value >= (1 << (record_length * 8)):
            return b"", 0x63, 0x00
        new_record = new_value.to_bytes(record_length, "big", signed=False)
        # Cyclic semantics: the new record becomes the most recent one
        # and the oldest record is overwritten in place. We model that
        # by appending then capping the list at its current length when
        # full -- a fresh cyclic EF starts with one zeroed record.
        node.records.append(new_record)
        max_records = max(1, len(node.records) - 1)
        if len(node.records) > max_records:
            node.records = node.records[-max_records:]
        self._persist_node_to_active_image(node)
        increment_padded = increment_value.to_bytes(record_length, "big", signed=False)
        return new_record + increment_padded, 0x90, 0x00

    def search_record(
        self,
        *,
        p1: int,
        p2: int,
        payload: bytes,
    ) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.7 SEARCH RECORD (simple search).

        P2 high 5 bits select an SFI (0 = current EF). P2 low 3 bits
        encode the search mode:

        - ``0x04`` simple search forward, starting at record P1.
        - ``0x05`` simple search backward, starting at record P1.
        - ``0x06`` enhanced search (per §11.1.7.4) -- not modelled;
          the form is accepted but treated as a forward simple search.

        The body is the byte sequence to look for. Successful search
        returns the matching record numbers (1 byte each) under SW
        ``90 00``; an empty match returns ``6A 83`` (record not found),
        which is what commercial UICCs report when the pattern is
        absent.
        """
        p1_value = int(p1) & 0xFF
        p2_value = int(p2) & 0xFF
        sfi = (p2_value >> 3) & 0x1F
        mode = p2_value & 0x07
        if sfi != 0:
            target_node = self._resolve_sfi_under_current(sfi)
            if target_node is None:
                return b"", 0x6A, 0x82
            self.state.current_node_id = target_node.node_id
        else:
            target_node = self.current_node()
        if target_node.kind != "ef" or target_node.structure != "linear-fixed":
            return b"", 0x69, 0x81
        if (int(target_node.lifecycle_state) & 0xFF) != 0x05:
            return b"", 0x62, 0x83
        record_count = len(target_node.records)
        if record_count == 0:
            return b"", 0x6A, 0x83
        pattern = bytes(payload or b"")
        if len(pattern) == 0:
            return b"", 0x6A, 0x80

        # Forward / backward iteration. Mode 0x06 is the enhanced
        # search variant; we collapse it onto forward simple search
        # because the four-byte search-indication header is rare and
        # the §11.1.7.4 result format (record + offset) is identical
        # to the simple form when no offset filter is applied.
        if mode == 0x05:
            start_index = max(1, p1_value)
            order = list(range(start_index, 0, -1))
        else:
            start_index = max(1, p1_value)
            order = list(range(start_index, record_count + 1))

        matches: list[int] = []
        for record_number in order:
            if record_number <= 0 or record_number > record_count:
                continue
            record_bytes = target_node.records[record_number - 1]
            if pattern in record_bytes:
                matches.append(record_number & 0xFF)
        if len(matches) == 0:
            return b"", 0x6A, 0x83
        return bytes(matches), 0x90, 0x00

    def _check_write_access(self, node: SimFileNode) -> bool:
        """Enforce the ``write_acl`` access condition on UPDATE BINARY /
        UPDATE RECORD (ETSI TS 102 221 §9, TS 31.102 §4).

        ``always`` -- backwards-compat default. ``never`` -- always
        denied. ``pin1`` -- requires CHV1 (P2=0x01) verified. ``adm``
        -- requires either an authenticated SCP03 session (the LPA
        acts as administrator) or any of the ADM CHVs (0x0A..0x0E)
        verified. Unknown values fall through as permissive so a
        legacy profile cannot soft-brick the modem path.
        """
        policy = str(getattr(node, "write_acl", "always") or "always").strip().lower()
        if policy in ("", "always"):
            return True
        if policy == "never":
            return False
        if policy == "pin1":
            chv = self.state.chv_references.get(0x01)
            return chv is not None and bool(chv.verified)
        if policy == "adm":
            if bool(getattr(self.state.scp03_session, "authenticated", False)):
                return True
            for reference in (0x0A, 0x0B, 0x0C, 0x0D, 0x0E):
                chv = self.state.chv_references.get(reference)
                if chv is not None and bool(chv.verified):
                    return True
            return False
        return True

    def find_node_by_path(self, path: tuple[str, ...]) -> SimFileNode | None:
        """Return the runtime node whose name path matches ``path``.

        ``path`` is the same MF-rooted tuple used by
        :class:`SimProfileFsNode`. The lookup is O(N) over the node
        table; callers in the hot APDU dispatch should cache by id
        if they need to write more than once per request.
        """
        target = tuple(str(part) for part in path or ())
        if len(target) == 0:
            return None
        for candidate in self.state.nodes.values():
            if self._runtime_node_path(candidate) == target:
                return candidate
        return None

    def write_ef_transparent_by_path(
        self,
        path: tuple[str, ...],
        data: bytes,
    ) -> bool:
        """Replace the body of a transparent EF identified by ``path``.

        Bypasses the ``write_acl`` gate -- callers (currently
        :meth:`AuthLogic.derive_5g_vector`) are administrative-context
        producers (KAUSF/KSEAF, KAUSF derivation counter) that the
        modem must never touch through ``UPDATE BINARY``. Persistence
        flows through :meth:`_persist_node_to_active_image` so the
        update survives a profile-store reload.

        Returns ``True`` on success, ``False`` if the node cannot be
        located, is not a transparent EF, or persistence threw an
        unexpected error.
        """
        node = self.find_node_by_path(path)
        if node is None or node.kind != "ef" or node.structure != "transparent":
            return False
        node.data = bytes(data or b"")
        try:
            self._persist_node_to_active_image(node)
        except Exception:
            return False
        return True

    def _runtime_node_path(self, node: SimFileNode) -> tuple[str, ...]:
        """Reconstruct an MF-rooted path for a runtime ``SimFileNode``.

        ``rebuild_runtime_filesystem`` builds runtime ids from the
        image path via ``_profile_path_node_id``; the inverse here
        walks ``parent_id`` chains so persistence does not depend on
        a particular id encoding. Cycle-safe through the ``seen``
        guard in case of corrupt parent links.
        """
        parts: list[str] = []
        seen: set[str] = set()
        current: SimFileNode | None = node
        while current is not None and current.node_id not in seen:
            seen.add(current.node_id)
            name = str(current.name or "").strip()
            if len(name) > 0:
                parts.append(name)
            parent_id = str(current.parent_id or "").strip()
            if len(parent_id) == 0:
                break
            current = self.state.nodes.get(parent_id)
        return tuple(reversed(parts))

    def _persist_node_to_active_image(self, node: SimFileNode) -> None:
        """Write a runtime ``SimFileNode`` mutation back to the active
        profile image and trigger a profile-store sync so the change
        survives an engine restart.

        Best-effort: a missing store path, a profile without an image,
        or a sync failure all degrade silently because the modem-side
        APDU has already succeeded by the time we get here -- a disk
        error must not desync the in-memory FS view.
        """
        store_path = str(self.state.profile_store_path or "").strip()
        if len(store_path) == 0:
            return
        active_profile = _resolve_active_profile(self.state)
        if active_profile is None:
            return
        image = active_profile.profile_image
        if image is None:
            return
        path = self._runtime_node_path(node)
        if len(path) == 0 or path[0] != "MF":
            return
        target_image_node: SimProfileFsNode | None = None
        for image_node in image.nodes:
            if tuple(image_node.path) == path:
                target_image_node = image_node
                break
        if target_image_node is None:
            target_image_node = SimProfileFsNode(
                path=path,
                name=node.name,
                kind=node.kind,
                fid=node.fid,
                aid=node.aid,
                label=node.label,
                structure=node.structure,
                sfi=node.sfi,
                write_acl=node.write_acl,
                lifecycle_state=int(getattr(node, "lifecycle_state", 0x05) or 0x05) & 0xFF,
            )
            image.nodes.append(target_image_node)
        target_image_node.data = bytes(node.data)
        target_image_node.records = [bytes(record) for record in node.records]
        target_image_node.write_acl = str(node.write_acl or "always")
        target_image_node.sfi = node.sfi
        target_image_node.lifecycle_state = int(getattr(node, "lifecycle_state", 0x05) or 0x05) & 0xFF
        try:
            from SIMCARD.profile_store import sync_profiles_to_store

            sync_profiles_to_store(store_path, self.state.profiles)
        except Exception:
            return

    def build_fcp(self, node: SimFileNode) -> bytes:
        """Build FCP per ETSI TS 102 221 §11.1.1.4.

        Descriptor bytes use the shareable flag (bit 7) so the FCP
        structure matches the response of commercial UICC references
        where MF/DF/ADF advertise 0x78 and EFs advertise 0x41 (transparent)
        or 0x42 (linear fixed), both with data-coding byte 0x21. The
        previous 0x38/0x01/0x02 encoding was a valid subset but strict
        terminals sometimes rely on the shareable bit when deciding
        whether a file can be accessed concurrently from multiple
        logical channels.

        8A (life-cycle status) is always emitted with 05
        (operational-activated); its absence can be rejected as an
        incomplete FCP by strict stacks and real UICCs always include
        it. 88 (short EF identifier) is emitted for EFs that have one
        assigned, with the SFI left-aligned in the high five bits per
        §11.1.1.4.7.
        """
        if node.kind == "adf" and self._is_security_domain(node):
            return self._build_isd_fci(node)
        if node.kind in ("mf", "df", "adf"):
            descriptor = b"\x78\x21"
        elif node.structure == "linear-fixed":
            descriptor = (
                bytes([0x42, 0x21])
                + node.record_length.to_bytes(2, "big", signed=False)
                + bytes([len(node.records) & 0xFF])
            )
        else:
            descriptor = b"\x41\x21"
        # Tag order: 82 83 [84] [A5] 8A 8B [80] [88] [C6]. Strict
        # baseband parsers walk the FCP linearly and tolerate missing
        # tags but reject unexpected ordering, so the order is kept
        # identical to the canonical UICC FCP format.
        body = tlv("82", descriptor)
        if len(node.fid) == 4:
            body += tlv("83", bytes.fromhex(node.fid))
        if len(node.aid) > 0:
            body += tlv("84", bytes.fromhex(node.aid))
        # ETSI TS 102 221 §11.1.1.4.6: Proprietary Information (A5)
        # carries the UICC characteristics byte (80) plus optional
        # application power consumption (83) and template version
        # (87). Real modems consult tag 80 inside A5 to confirm the
        # card identifies itself as a UICC; missing it makes strict
        # baseband stacks fall back to legacy-SIM enumeration or
        # abort. Emitted for MF/DF/non-SD ADF only -- ISD-R/ECASD
        # have their own FCI builder.
        is_dir_node = node.kind in ("mf", "df", "adf")
        is_security_domain = is_dir_node and self._is_security_domain(node)
        if is_dir_node and not is_security_domain:
            body += self._build_proprietary_information_template()
        # FCP tag 8A advertises the actual lifecycle so a terminal that
        # caches the FCP from a previous SELECT can detect a subsequent
        # DEACTIVATE FILE. Older simulator builds always emitted 0x05
        # (operational-activated); we now reflect the runtime state.
        body += tlv("8A", bytes((int(node.lifecycle_state) & 0xFF,)))
        # ETSI TS 102 221 §11.1.1.4.7: every regular file (EF, DF, MF,
        # non-SD ADF) advertises its security attributes via 8B
        # (referenced) so the terminal can resolve access conditions
        # without having to walk the file tree. EF FCPs from
        # commercial cards always include 8B even though strict
        # readers seldom dereference EF_ARR during normal boot --
        # leaving 8B out causes some basebands to assume "no rules =
        # default-deny" and skip the file silently.
        if not is_security_domain:
            body += self._build_security_attributes_referenced(node)
        if node.kind == "ef":
            size = node.total_size
            if size > 0:
                # 80 always emits 2-byte file size for transparent EFs
                # to match commercial UICC FCPs; the previous 1-byte
                # encoding was legal but unusual and confused some
                # modem TLV walkers that hard-coded the 2-byte length.
                body += tlv("80", size.to_bytes(2, "big", signed=False))
            if node.sfi is not None and (int(node.sfi) & 0x1F) != 0:
                body += tlv("88", bytes([(int(node.sfi) & 0x1F) << 3]))
        if is_dir_node and not is_security_domain:
            # ETSI TS 102 221 §11.1.1.4.9 PIN Status Template DO -- only
            # makes sense at MF/DF/ADF level (EFs do not carry PIN
            # state of their own).
            body += self._build_pin_status_template_do(node)
        return tlv("62", body)

    def _build_proprietary_information_template(self) -> bytes:
        """ETSI TS 102 221 §11.1.1.4.6 Proprietary Information (A5).

        The MF/DF/ADF FCP advertises:
            80 01 71               UICC Characteristics: clock-stop
                                   high/low allowed, max 5 MHz; matches
                                   the value commercial UICCs use when
                                   the ATR's TA1=0x96 declares Fi=512
                                   Di=32 (~5 MHz).
            83 04 00 03 79 70      Application Power Consumption:
                                   class B 3 V, 0x7970 mA*100us.
            87 01 01               Template version 1.

        Modems use 80 inside A5 to discriminate UICC from legacy SIM;
        without it the stack often refuses to issue TERMINAL CAPABILITY
        and aborts the boot sequence after MF discovery.
        """
        body = tlv("80", bytes([0x71]))
        body += tlv("83", bytes.fromhex("00037970"))
        body += tlv("87", bytes([0x01]))
        return tlv("A5", body)

    def _build_security_attributes_referenced(self, node: SimFileNode) -> bytes:
        """ETSI TS 102 221 §11.1.1.4.7 referenced security attributes.

        Tag 8B references EF_ARR with FID + record number. Two
        conventions co-exist on commercial UICCs:

        * The *global* EF_ARR at MF/2F06 -- this is the anchor used by
          MF, every DF, every ADF top-level FCP, and every EF that
          lives directly under MF (2Fxx files).
        * A *local* EF_ARR at <DF>/6F06 -- this is the anchor used by
          EFs that live under a DF or ADF (6Fxx / 4Fxx files). Each
          DF/ADF carries its own EF_ARR; the records re-use the same
          numbering scheme as the global one.

        The record number is derived from the node's ``write_acl`` so
        the terminal sees a self-consistent reference even though the
        simulator does not actually expose a populated EF_ARR. Record
        0x0E is reserved for top-level FCPs (MF/DF/ADF) because real
        cards reserve that record for the full PIN1/Universal-PIN/ADM1
        cascade.
        """
        write_acl = str(getattr(node, "write_acl", "") or "always").strip().lower()
        if node.kind in ("mf", "df", "adf"):
            record_byte = 0x0E
        elif write_acl == "pin1":
            record_byte = 0x02
        elif write_acl == "adm":
            record_byte = 0x0A
        elif write_acl == "never":
            record_byte = 0x06
        else:
            record_byte = 0x01
        ef_arr_fid = self._resolve_ef_arr_fid(node)
        return tlv("8B", bytes([ef_arr_fid >> 8, ef_arr_fid & 0xFF, record_byte]))

    def _resolve_ef_arr_fid(self, node: SimFileNode) -> int:
        """Pick the EF_ARR FID whose access rules govern ``node``.

        EFs whose parent is the MF reference the global EF_ARR at
        2F06; EFs (and DFs/ADFs) that hang off a DF or ADF reference
        the local 6F06. MF itself, top-level DFs, and top-level ADFs
        all reference 2F06 (the global table) per the standard UICC
        convention.
        """
        if node.kind in ("mf", "df", "adf"):
            return 0x2F06
        parent_id = str(getattr(node, "parent_id", "") or "").strip()
        parent_node = self.state.nodes.get(parent_id) if parent_id else None
        if parent_node is None:
            return 0x2F06
        if parent_node.kind == "mf":
            return 0x2F06
        return 0x6F06

    def _build_pin_status_template_do(self, node: SimFileNode) -> bytes:
        """ETSI TS 102 221 §11.1.1.4.9 PIN Status Template DO (tag C6).

        Encoding rules per §9.5.2:

        * The PS_DO bitmap (tag 90) maps the *position* of each "Key
          Reference" entry (tag 83) to a bit. Bit b8 of byte 1 = first
          83 entry, bit b7 = second 83 entry, etc. A bit set to 1
          means the PIN at that reference is currently *enabled*
          (VERIFY required); 0 means disabled.

        * At the MF level commercial UICCs declare PIN1 (key ref 0x01)
          + ADM1 (0x0A) with PIN1 disabled and ADM1 enabled, because
          PIN1 verification happens at ADF level, not MF. We mirror
          that so terminals proceed past MF to TERMINAL CAPABILITY
          without trying to VERIFY PIN1 globally.

        * At the ADF/DF level we declare the PIN1 / Universal-PIN /
          ADM1 triplet. The bitmap is computed from
          ``state.chv_references[...].enabled`` so DISABLE PIN /
          ENABLE PIN APDUs flip the advertisement on the next FCP
          retrieval.
        """
        chv = self.state.chv_references
        if node.kind == "mf":
            bitmap = 0x40
            return tlv(
                "C6",
                tlv("90", bytes([bitmap]))
                + tlv("83", bytes([0x01]))
                + tlv("83", bytes([0x0A])),
            )
        entries: list[int] = [0x01]
        if 0x81 in chv:
            entries.append(0x81)
        entries.append(0x0A)
        bitmap = 0
        for position, reference in enumerate(entries):
            chv_state = chv.get(reference)
            enabled_flag = True
            if chv_state is not None:
                enabled_flag = bool(getattr(chv_state, "enabled", True))
            if reference == 0x0A:
                enabled_flag = True
            if enabled_flag:
                bitmap |= 0x80 >> position
        body = tlv("90", bytes([bitmap & 0xFF]))
        for reference in entries:
            body += tlv("83", bytes([reference & 0xFF]))
        return tlv("C6", body)

    def _is_security_domain(self, node: SimFileNode) -> bool:
        aid_hex = str(node.aid or "").strip().upper()
        if len(aid_hex) == 0:
            return False
        isdr_aid = str(self.state.isdr_aid or "").strip().upper()
        ecasd_aid = str(self.state.ecasd_aid or "").strip().upper()
        mno_aid = str(self.state.mno_sd_aid or "").strip().upper()
        return aid_hex in (isdr_aid, ecasd_aid, mno_aid)

    def _build_isd_fci(self, node: SimFileNode) -> bytes:
        """FCI template per SGP.22 §5.7.1 / GP Card Spec v2.3.1 §11.1.5.

        ISD-R / ECASD / MNO-SD SHALL respond to SELECT with an FCI (tag 6F)
        carrying at minimum the AID (84) and a proprietary A5 block with
        9F65 (max buffer). ISD-R additionally advertises E0 (extended card
        resources) and E1 (profile-installation result envelope size).
        """
        aid_hex = str(node.aid or "").strip().upper()
        body = tlv("84", bytes.fromhex(aid_hex))

        max_buffer = 0x00FF
        proprietary = tlv("9F65", max_buffer.to_bytes(2, "big", signed=False))
        body += tlv("A5", proprietary)

        isdr_aid = str(self.state.isdr_aid or "").strip().upper()
        if aid_hex == isdr_aid:
            ext = self.state.euicc_info.ext_card_resources
            ext_payload = (
                tlv("81", bytes([ext.system_apps_count & 0xFF]))
                + tlv("82", ext.free_nvm.to_bytes(3, "big", signed=False))
                + tlv("83", ext.free_ram.to_bytes(2, "big", signed=False))
            )
            body += tlv("E0", ext_payload)
            body += tlv("E1", tlv("80", (0x06C0).to_bytes(2, "big", signed=False)))

        return tlv("6F", body)
