# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""RSP ASN.1 compiled with the SGP.22 v3.1 StoreMetadataRequest members present.

Upstream pySim declares `StoreMetadataRequest` with the nine members SGP.22 v2
specifies. v3.1 section 5.5.3 adds ten more, and `asn1tools` drops a payload key
its schema does not define without raising, so encoding against the stock schema
returns the bytes it would have produced without the field and reports nothing.

`pySim.esim.compile_asn1_subdir` concatenates the ASN.1 files in a directory and
hands the string to `asn1tools.compile_string`, so the missing declarations can
be supplied at compile time instead of by patching the installed package. The
schema extension itself, its repro and its validation output are logged for
upstream in `upstream_patches/osmocom-pysim-rsp-v3-metadata/`; this module is the
YggdraSIM-side half that makes a stock `pip install` behave correctly meanwhile.

The substitution is scoped to the `StoreMetadataRequest` block: its anchor line
appears in three types, and a first-match replace patches the wrong one and
silently yields a nine-member schema. When upstream adds the members the anchor
stops matching, the supplement is skipped, and the result is the same either
way. `rsp_type_members` in `pysim_support` reads the compiled member set back,
so a supplement that fails to apply is reported at the point of use rather than
losing fields quietly.
"""

from __future__ import annotations

from typing import Any

# The final member of the v2 StoreMetadataRequest, and the closing brace of the
# SEQUENCE. Matched inside the StoreMetadataRequest block only.
_V2_TAIL = "    profilePolicyRules [25] PprIds OPTIONAL -- Tag '99'\n}"

# SGP.22 v3.1 section 5.5.3 and Annex H. `VendorSpecificExtension` is published
# as an information object class; `asn1tools` has no OPENTYPE to resolve, so the
# two fields are typed OBJECT IDENTIFIER and ANY. The wire encoding is the same
# -- an OID followed by the vendor's own DER -- but nothing validates that the
# DER matches the OID's registered type, so callers pass raw bytes.
_V3_SUPPLEMENT = """    profilePolicyRules [25] PprIds OPTIONAL, -- Tag '99'
    serviceSpecificDataStoredInEuicc [34] VendorSpecificExtension OPTIONAL, -- Tag 'BF22'
    serviceSpecificDataNotStoredInEuicc [35] VendorSpecificExtension OPTIONAL, -- Tag 'BF23'
    rpmConfiguration [26] RpmConfiguration OPTIONAL, -- Tag 'BA'
    hriServerAddress [27] UTF8String OPTIONAL, -- Tag '9B'
    serviceProviderMessage [30] LocalisedTextMessage OPTIONAL, -- Tag 'BE'
    lprConfiguration [28] LprConfiguration OPTIONAL, -- Tag 'BC'
    enterpriseConfiguration [29] EnterpriseConfiguration OPTIONAL, -- Tag 'BD'
    serviceDescription [31] ServiceDescription OPTIONAL, -- Tag '9F1F'
    deviceChangeConfiguration [32] DeviceChangeConfiguration OPTIONAL, -- Tag 'BF20'
    estimatedProfileSize [33] INTEGER OPTIONAL -- Tag '9F21'
}

VendorSpecificExtension ::= SEQUENCE OF SEQUENCE {
    vendorOid [0] OBJECT IDENTIFIER,
    vendorSpecificData [1] ANY
}

RpmType ::= BIT STRING {
    enable(0), disable(1), delete(2), listProfileInfo(3), contactPcmp(4)
}

RpmConfiguration ::= SEQUENCE {
    managingDpList [0] SEQUENCE OF SEQUENCE {
        managingDpOid [0] OBJECT IDENTIFIER,
        rpmType [1] RpmType OPTIONAL,
        tagList [APPLICATION 28] OCTET STRING OPTIONAL
    },
    pollingAddress [1] UTF8String OPTIONAL, -- Tag '81'
    allowedCiPKId [2] SubjectKeyIdentifier OPTIONAL,
    profileOwnerOid [3] OBJECT IDENTIFIER
}

LocalisedTextMessage ::= SEQUENCE {
    languageTag UTF8String DEFAULT "en", -- RFC 5646 language tag
    message UTF8String
}

LprConfiguration ::= SEQUENCE {
    pcmpAddress [0] UTF8String,
    dpiEnable [1] UTF8String OPTIONAL,
    triggerLprOnEnableProfile [2] NULL OPTIONAL
}

EnterpriseConfiguration ::= SEQUENCE {
    enterpriseOid [0] OBJECT IDENTIFIER,
    enterpriseName [1] UTF8String (SIZE(0..64)),
    enterpriseRules [2] SEQUENCE {
        enterpriseRuleBits [0] BIT STRING {
            referenceEnterpriseRule (0),
            priorityEnterpriseProfile (1),
            onlyEnterpriseProfilesCanBeInstalled (2)
        },
        numberOfNonEnterpriseProfiles [1] INTEGER
    } OPTIONAL
}

ServiceDescription ::= BIT STRING {
    voice (0), data (1)
}

DeviceChangeConfiguration ::= CHOICE {
    requestToDp [0] SEQUENCE {
        smdpAddressForDc UTF8String,
        allowedCiPKId SubjectKeyIdentifier OPTIONAL,
        eidRequired NULL OPTIONAL,
        tacRequired NULL OPTIONAL
    },
    usingStoredAc [1] SEQUENCE {
        activationCodeForDc UTF8String (SIZE(0..255)),
        deleteOldProfile NULL OPTIONAL
    }
}"""

_STORE_METADATA = "StoreMetadataRequest ::="


def read_rsp_schema_text() -> str:
    """Return the concatenated RSP ASN.1 shipped by the resolved pySim."""
    from importlib import resources

    # Explicit encoding, unlike pySim's own reader: the ASN.1 is UTF-8 and a
    # Windows console locale would otherwise decode it as cp1252.
    parts: list[str] = []
    directory = resources.files("pySim.esim").joinpath("asn1").joinpath("rsp")
    for entry in directory.iterdir():
        parts.append(entry.read_text(encoding="utf-8"))
    return "\n".join(parts) + "\n"


def apply_v3_metadata_supplement(schema_text: str) -> str:
    """Declare the v3.1 StoreMetadataRequest members if the schema lacks them.

    Returns the text unchanged when the anchor is absent, which is what an
    upstream that already carries the members looks like.
    """
    start = schema_text.find(_STORE_METADATA)
    if start < 0:
        return schema_text
    end = schema_text.find("\n}", start)
    if end < 0:
        return schema_text
    end += 2

    block = schema_text[start:end]
    if _V2_TAIL not in block:
        return schema_text
    return schema_text[:start] + block.replace(_V2_TAIL, _V3_SUPPLEMENT, 1) + schema_text[end:]


def compile_rsp_specification() -> Any:
    """Compile the RSP schema, v3.1 metadata members included.

    Raises whatever ``asn1tools`` raises; the caller decides what an
    uncompilable schema means for it.
    """
    import asn1tools

    return asn1tools.compile_string(
        apply_v3_metadata_supplement(read_rsp_schema_text()), codec="der"
    )
