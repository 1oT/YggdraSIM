# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""X.509 name and extension tables: RFC 5280 object identifiers, key usage bits, general name forms.

One home for the tables a certificate viewer and a certificate builder both
read. Object identifiers are dotted strings, names are the ASN.1 identifiers
RFC 5280 gives them, and every table is the whole clause: a consumer that
supports fewer rows says which ones beside its own code.
"""

from __future__ import annotations

from typing import NamedTuple

__all__ = [
    "ACCESS_METHODS",
    "ANY_POLICY",
    "DIRECTORY_STRING_TYPES",
    "EXTENDED_KEY_USAGES",
    "GENERAL_NAME_FORMS",
    "ID_AD",
    "ID_CE",
    "ID_KP",
    "ID_PE",
    "ID_PKIX",
    "KEY_USAGE_BITS",
    "NAME_ATTRIBUTES",
    "STANDARD_EXTENSIONS",
    "AttributeInfo",
    "ExtensionInfo",
    "GeneralNameForm",
    "KeyUsageBit",
]

# RFC 5280 Appendix A.1: id-pkix ::= {1 3 6 1 5 5 7}, id-pe ::= {id-pkix 1}, id-kp ::= {id-pkix 3},
# id-ad ::= {id-pkix 48}; Appendix A.2: id-ce ::= {2 5 29}.
ID_PKIX = "1.3.6.1.5.5.7"
ID_PE = ID_PKIX + ".1"
ID_KP = ID_PKIX + ".3"
ID_AD = ID_PKIX + ".48"
ID_CE = "2.5.29"

#: RFC 5280 §4.2.1.4: anyPolicy ::= {id-ce-certificatePolicies 0}.
ANY_POLICY = ID_CE + ".32.0"


class ExtensionInfo(NamedTuple):
    """One certificate extension: its identifier, its ASN.1 name without the id-ce- / id-pe- prefix, its clause."""

    oid: str
    name: str
    heading: str
    clause: str


#: RFC 5280 §4.2.1.1 - §4.2.1.15 (standard extensions) and §4.2.2.1 - §4.2.2.2 (private Internet
#: extensions), in clause order; the identifiers are those of Appendix A.2.
STANDARD_EXTENSIONS: tuple[ExtensionInfo, ...] = tuple(
    ExtensionInfo(**row)
    for row in (
        {"clause": "4.2.1.1", "oid": ID_CE + ".35", "name": "authorityKeyIdentifier", "heading": "Authority Key Identifier"},
        {"clause": "4.2.1.2", "oid": ID_CE + ".14", "name": "subjectKeyIdentifier", "heading": "Subject Key Identifier"},
        {"clause": "4.2.1.3", "oid": ID_CE + ".15", "name": "keyUsage", "heading": "Key Usage"},
        {"clause": "4.2.1.4", "oid": ID_CE + ".32", "name": "certificatePolicies", "heading": "Certificate Policies"},
        {"clause": "4.2.1.5", "oid": ID_CE + ".33", "name": "policyMappings", "heading": "Policy Mappings"},
        {"clause": "4.2.1.6", "oid": ID_CE + ".17", "name": "subjectAltName", "heading": "Subject Alternative Name"},
        {"clause": "4.2.1.7", "oid": ID_CE + ".18", "name": "issuerAltName", "heading": "Issuer Alternative Name"},
        {"clause": "4.2.1.8", "oid": ID_CE + ".9", "name": "subjectDirectoryAttributes", "heading": "Subject Directory Attributes"},
        {"clause": "4.2.1.9", "oid": ID_CE + ".19", "name": "basicConstraints", "heading": "Basic Constraints"},
        {"clause": "4.2.1.10", "oid": ID_CE + ".30", "name": "nameConstraints", "heading": "Name Constraints"},
        {"clause": "4.2.1.11", "oid": ID_CE + ".36", "name": "policyConstraints", "heading": "Policy Constraints"},
        {"clause": "4.2.1.12", "oid": ID_CE + ".37", "name": "extKeyUsage", "heading": "Extended Key Usage"},
        {"clause": "4.2.1.13", "oid": ID_CE + ".31", "name": "cRLDistributionPoints", "heading": "CRL Distribution Points"},
        {"clause": "4.2.1.14", "oid": ID_CE + ".54", "name": "inhibitAnyPolicy", "heading": "Inhibit anyPolicy"},
        {"clause": "4.2.1.15", "oid": ID_CE + ".46", "name": "freshestCRL", "heading": "Freshest CRL"},
        {"clause": "4.2.2.1", "oid": ID_PE + ".1", "name": "authorityInfoAccess", "heading": "Authority Information Access"},
        {"clause": "4.2.2.2", "oid": ID_PE + ".11", "name": "subjectInfoAccess", "heading": "Subject Information Access"},
    )
)


class KeyUsageBit(NamedTuple):
    """One KeyUsage bit: its number, its name, and the attribute the ``cryptography`` class holds it in."""

    bit: int
    name: str
    attribute: str


#: RFC 5280 §4.2.1.3 KeyUsage ::= BIT STRING, bits 0 to 8. The last two carry meaning only with
#: keyAgreement set.
KEY_USAGE_BITS: tuple[KeyUsageBit, ...] = (
    KeyUsageBit(0, "digitalSignature", "digital_signature"),
    KeyUsageBit(1, "nonRepudiation", "content_commitment"),
    KeyUsageBit(2, "keyEncipherment", "key_encipherment"),
    KeyUsageBit(3, "dataEncipherment", "data_encipherment"),
    KeyUsageBit(4, "keyAgreement", "key_agreement"),
    KeyUsageBit(5, "keyCertSign", "key_cert_sign"),
    KeyUsageBit(6, "cRLSign", "crl_sign"),
    KeyUsageBit(7, "encipherOnly", "encipher_only"),
    KeyUsageBit(8, "decipherOnly", "decipher_only"),
)

#: RFC 5280 §4.2.1.12: anyExtendedKeyUsage ::= {id-ce-extKeyUsage 0} and the six id-kp purposes.
EXTENDED_KEY_USAGES: dict[str, str] = {
    ID_CE + ".37.0": "anyExtendedKeyUsage",
    ID_KP + ".1": "id-kp-serverAuth",
    ID_KP + ".2": "id-kp-clientAuth",
    ID_KP + ".3": "id-kp-codeSigning",
    ID_KP + ".4": "id-kp-emailProtection",
    ID_KP + ".8": "id-kp-timeStamping",
    ID_KP + ".9": "id-kp-OCSPSigning",
}

#: RFC 5280 §4.2.2.1 (id-ad-ocsp, id-ad-caIssuers) and §4.2.2.2 (id-ad-timeStamping,
#: id-ad-caRepository): the accessMethod identifiers of Appendix A.1.
ACCESS_METHODS: dict[str, str] = {
    ID_AD + ".1": "id-ad-ocsp",
    ID_AD + ".2": "id-ad-caIssuers",
    ID_AD + ".3": "id-ad-timeStamping",
    ID_AD + ".5": "id-ad-caRepository",
}


class GeneralNameForm(NamedTuple):
    """One GeneralName alternative: its context tag, its name, and the prefix a listing writes it with."""

    tag: int
    name: str
    prefix: str


#: RFC 5280 §4.2.1.6 GeneralName ::= CHOICE, alternatives [0] to [8]. The prefixes are the ones the
#: certificate views print; x400Address and ediPartyName have none.
GENERAL_NAME_FORMS: tuple[GeneralNameForm, ...] = (
    GeneralNameForm(0, "otherName", "otherName"),
    GeneralNameForm(1, "rfc822Name", "email"),
    GeneralNameForm(2, "dNSName", "DNS"),
    GeneralNameForm(3, "x400Address", ""),
    GeneralNameForm(4, "directoryName", "DirName"),
    GeneralNameForm(5, "ediPartyName", ""),
    GeneralNameForm(6, "uniformResourceIdentifier", "URI"),
    GeneralNameForm(7, "iPAddress", "IP"),
    GeneralNameForm(8, "registeredID", "RID"),
)


class AttributeInfo(NamedTuple):
    """One distinguished-name attribute type: its identifier, its name, and its RFC 4514 short name when it has one."""

    oid: str
    name: str
    short: str


#: The attribute types of a certificate name. RFC 5280 §4.1.2.4: the seven an implementation MUST be
#: prepared to receive (country to serial number), the seven it SHOULD (locality to generation
#: qualifier) and domainComponent; §4.1.2.6: the legacy emailAddress. Then the two of the RFC 4514 §3
#: short-name table that RFC 5280 does not list. Identifiers as in RFC 5280 Appendix A.1.
NAME_ATTRIBUTES: tuple[AttributeInfo, ...] = (
    AttributeInfo("2.5.4.6", "countryName", "C"),
    AttributeInfo("2.5.4.10", "organizationName", "O"),
    AttributeInfo("2.5.4.11", "organizationalUnitName", "OU"),
    AttributeInfo("2.5.4.46", "dnQualifier", ""),
    AttributeInfo("2.5.4.8", "stateOrProvinceName", "ST"),
    AttributeInfo("2.5.4.3", "commonName", "CN"),
    AttributeInfo("2.5.4.5", "serialNumber", ""),
    AttributeInfo("2.5.4.7", "localityName", "L"),
    AttributeInfo("2.5.4.12", "title", ""),
    AttributeInfo("2.5.4.4", "surname", ""),
    AttributeInfo("2.5.4.42", "givenName", ""),
    AttributeInfo("2.5.4.43", "initials", ""),
    AttributeInfo("2.5.4.65", "pseudonym", ""),
    AttributeInfo("2.5.4.44", "generationQualifier", ""),
    AttributeInfo("0.9.2342.19200300.100.1.25", "domainComponent", "DC"),
    AttributeInfo("1.2.840.113549.1.9.1", "emailAddress", ""),
    AttributeInfo("2.5.4.9", "streetAddress", "STREET"),
    AttributeInfo("0.9.2342.19200300.100.1.1", "userId", "UID"),
)

#: RFC 5280 §4.1.2.4 DirectoryString ::= CHOICE, in the order of the definition. A conforming CA uses
#: printableString or utf8String; the other three are kept for names issued earlier.
DIRECTORY_STRING_TYPES: tuple[str, ...] = (
    "teletexString",
    "printableString",
    "universalString",
    "utf8String",
    "bmpString",
)
