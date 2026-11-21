# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

"""Pre-personalization fill patterns for EFs a Profile Package leaves unwritten.

A ``fillFileOffset`` moves the write head without writing (TCA SAIP 8.3.5), so
the bytes it skips keep whatever the file was created with. When the Fcp carries
no fill/repeat pattern and no template default resolves, TS 102 222 does not say
what a newly created EF contains -- the value is left to the eUICC. Declaring the
pattern removes that ambiguity.

The pattern is not uniformly ``FF``. 3GPP TS 31.102 Annex E and TS 51.011 Annex D
("Suggested contents of the EFs at pre-personalization") give a per-file value,
and several are not erased: EF.SMS and the extension records open with a ``00``
status or record-type byte, the ciphering/integrity key files with the ``07``
"no key" sequence number, and the VGCS/VBS ciphering-algorithm files are
all-zero. Filling those with ``FF`` would encode a value no decoder reads back.

Both annexes write the value in a prefix-then-repeat-last form (``'00FF...FF'``,
``'07FF...FF'``, ``'FF...FF'``), which is how ETSI TS 102 222 6.3.2.2 defines the
Filling Pattern (tag ``C1``): the first W-1 bytes come from the pattern and every
remaining byte repeats its last byte. Each entry below is the literal
``fillPattern`` to emit, not the expanded file content.

**Entries are keyed by file name, never by file identifier alone.** A ``6Fxx``
identifier is allocated per DF, so the same number names different files in
different places: ``6F02`` is EF.IMPI under ADF.ISIM but a USIM threshold file in
the annex, ``6F09`` is EF.P-CSCF as well as EF.KeysPS, and ``6F40`` through
``6F7B`` are all EF.ICON inside DF.GRAPHICS. Keying on the identifier would give
EF.ICON the extension records' ``00FF`` and EF.IMPI a threshold pattern. The
identifier is still required to match, as a second check on the name.

Scope, deliberately narrow:

* Only files with **no** template default. TCA SAIP 8.3.3 -- "a repeat or fill
  pattern provided within the respective Fcp shall overwrite the default content
  completely" -- so emitting a pattern for a template-derived EF would destroy
  the template's own content.
* Only rows whose annex description maps onto one file this toolchain names.
  Rows for files that appear under no template (EF.ADN, EF.LND, EF.EXT1, the
  legacy ``6F02``/``6F30`` USIM rows) are omitted rather than guessed at.
* Only identifiers whose annex rows **agree**. Where TS 31.102 and TS 51.011 give
  different values for one identifier the row is dropped, not resolved by
  preference.
* Nothing for the rows the annexes call "operator dependent" / "card issuer
  dependent" -- EF.ICCID, EF.IMSI, EF.ARR, EF.UST, EF.SPN among them. No entry
  means no pattern, which is the behaviour that shipped before this table.

``tests/test_saip_ef_default_fill.py`` re-checks every row against the converted
specification text when that corpus is present.
"""

from __future__ import annotations

# name -> (file identifier, TS 102 222 tag 'C1' Filling Pattern).
# Sources: 3GPP TS 31.102 Annex E, 3GPP TS 51.011 Annex D.
_FILL_PATTERN_BY_NAME: dict[str, tuple[str, str]] = {
    # Erased -- the file is unused until something writes it.
    "EF.PL": ("2F05", "FF"),                 # Preferred / extended language
    "EF.DCK": ("6F2C", "FF"),                # De-personalization control keys
    "EF.CNL": ("6F32", "FF"),                # Co-operative network list
    "EF.FDN": ("6F3B", "FF"),                # Fixed dialling numbers
    "EF.MSISDN": ("6F40", "FF"),             # MSISDN storage
    "EF.SMSP": ("6F42", "FF"),               # SMS parameters
    "EF.SMSS": ("6F43", "FF"),               # SMS status
    "EF.CBMI": ("6F45", "FF"),               # Cell broadcast message identifier
    "EF.CBMID": ("6F48", "FF"),              # CBMI for data download
    "EF.SDN": ("6F49", "FF"),                # Service dialling numbers
    "EF.BDN": ("6F4D", "FF"),                # Barred dialling numbers
    "EF.CCP2": ("6F4F", "FF"),               # Capability configuration params 2
    "EF.CBMIR": ("6F50", "FF"),              # CBMI range selection
    "EF.CMI": ("6F58", "FF"),                # Comparison method information
    "EF.FPLMN": ("6F7B", "FF"),              # Forbidden PLMNs
    "EF.HIDDENKEY": ("6FC3", "FF"),          # Key for hidden phonebook entries
    "EF.NETPAR": ("6FC4", "FF"),             # Network parameters
    "EF.MMSICP": ("6FD0", "FF"),             # MMS issuer connectivity parameters
    "EF.MMSUP": ("6FD1", "FF"),              # MMS user preferences
    "EF.MMSUCP": ("6FD2", "FF"),             # MMS user connectivity parameters
    "EF.NIA": ("6FD3", "FF"),                # Network's indication of alerting
    "EF.GBABP": ("6FD6", "FF"),              # GBA bootstrapping parameters
    "EF.MSK": ("6FD7", "FF"),                # MBMS service keys list
    "EF.MUK": ("6FD8", "FF"),                # MBMS user key
    "EF.GBANL": ("6FDA", "FF"),              # GBA NAF list
    "EF.NAFKCA": ("6FDD", "FF"),             # NAF key centre address
    "EF.EPSNSC": ("6FE4", "FF"),             # EPS NAS security context
    "EF.FDNURI": ("6FED", "FF"),             # FDN URI
    "EF.BDNURI": ("6FEE", "FF"),             # BDN URI
    "EF.SDNURI": ("6FEF", "FF"),             # SDN URI
    "EF.IPS": ("6FF1", "FF"),                # IMEI(SV) pairing status
    "EF.IPD": ("6FF2", "FF"),                # IMEI(SV) pairing devices
    "EF.EPDGID": ("6FF3", "FF"),             # Home ePDG identifier
    "EF.EPDGSELECTION": ("6FF4", "FF"),      # ePDG selection information
    "EF.EPDGIDEM": ("6FF5", "FF"),           # Emergency ePDG identifier
    "EF.EPDGIDEMSEL": ("6FF6", "FF"),        # Emergency ePDG selection info

    # A leading status / record-type byte of '00' means "slot unused"; the
    # rest of the record is erased. Filling byte 1 with 'FF' would encode a
    # status value no decoder defines.
    "EF.SMS": ("6F3C", "00FF"),              # Short messages
    "EF.SMSR": ("6F47", "00FF"),             # Short message status reports
    "EF.EXT2": ("6F4B", "00FF"),             # Extension 2
    "EF.EXT3": ("6F4C", "00FF"),             # Extension 3
    "EF.EXT5": ("6F4E", "00FF"),             # Extension 5
    "EF.EXT4": ("6F55", "00FF"),             # Extension 4
    "EF.EXT6": ("6FC8", "00FF"),             # Extension 6
    "EF.EXT8": ("6FCF", "00FF"),             # Extension 8
    "EF.ACL": ("6F57", "00FF"),              # APN control list
    "EF.SPNI": ("6FDE", "00FF"),             # Service provider name icon
    "EF.PNNI": ("6FDF", "00FF"),             # PLMN network name icon
    "EF.MMSN": ("6FCE", "000000FF"),         # MMS notification

    # '07' is the "no key available" cipher key sequence number
    # (3GPP TS 24.008 10.5.1.2), so the file advertises no cached key.
    "EF.KEYS": ("6F08", "07FF"),             # Ciphering and integrity keys
    "EF.KEYSPS": ("6F09", "07FF"),           # ... for the PS domain

    # All-zero: the algorithm identifier is a value, not an absence.
    "EF.VGCSCA": ("6FD4", "00"),             # Voice group call ciphering alg
    "EF.VBSCA": ("6FD5", "00"),              # Voice broadcast ciphering alg
}

# EF.Kc / EF.KcGPRS are written 'FF...FF07' -- suffix-anchored, which tag 'C1'
# expresses only while the pattern spans the whole file. Both are nine bytes:
# eight key bytes plus the CKSN, and value 7 marks "no key available". The TCA
# SAIP DF GSM-ACCESS template (9.5.4) ships the same nine bytes as its default.
_EXACT_SIZE_PATTERN_BY_NAME: dict[str, tuple[str, str, int]] = {
    "EF.KC": ("4F20", "FFFFFFFFFFFFFFFF07", 9),
    "EF.KCGPRS": ("4F52", "FFFFFFFFFFFFFFFF07", 9),
}


def _normalise_fid(value: object) -> str:
    if isinstance(value, int):
        return f"{value:04X}"
    text = str(value or "").strip().upper().replace(" ", "")
    return text if len(text) == 4 else ""


def default_fill_pattern(
    file_name: object,
    *,
    file_id: object = None,
    file_size: int | None = None,
) -> bytes | None:
    """Return the ``fillPattern`` bytes for ``file_name``, or ``None``.

    ``file_id`` is checked against the table when supplied; a name that arrives
    at an unexpected identifier is refused rather than patterned. ``None`` is
    the answer for every file the annexes call operator dependent and for every
    name not tabulated, and callers emit no pattern in that case.
    """
    name = str(file_name or "").strip().upper()
    if len(name) == 0:
        return None
    fid = _normalise_fid(file_id)

    sized = _EXACT_SIZE_PATTERN_BY_NAME.get(name)
    if sized is not None:
        expected_fid, pattern, exact_size = sized
        if len(fid) > 0 and fid != expected_fid:
            return None
        if file_size is None or int(file_size) != exact_size:
            return None
        return bytes.fromhex(pattern)

    entry = _FILL_PATTERN_BY_NAME.get(name)
    if entry is None:
        return None
    expected_fid, pattern = entry
    if len(fid) > 0 and fid != expected_fid:
        return None
    return bytes.fromhex(pattern)
