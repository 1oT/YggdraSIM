# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""RSP certificate roles carried in the certificatePolicies extension.

SGP.22 v3.1 section 4.5.2.1 puts one ``id-rspRole-*`` OID into the critical
certificatePolicies extension of every RSP certificate, and section 2.4a.1.0
defines the arcs under ``id-rspRole ::= {id-rsp-cert-objects 1}`` with
``id-rsp-cert-objects ::= {id-rsp 2}`` and ``id-rsp`` the GSMA RSP arc
``{joint-iso-itu-t(2) international-organizations(23) gsma(146) rsp(1)}``
(Annex K), so every role sits under 2.23.146.1.2.1. The neighbouring arc
2.23.143.1 is the TCA eUICC Profile Package arc (SAIP template OIDs) and
names no certificate role. The ``-v2`` values mark a Variant O chain.
"""

from __future__ import annotations

from cryptography import x509 as crypto_x509
from cryptography.x509.oid import ExtensionOID

ID_RSP = "2.23.146.1"
ID_RSP_ROLE = ID_RSP + ".2.1"

# Keys follow the ``id-rspRole-`` suffixes of SGP.22 v3.1 section 2.4a.1.0.
RSP_ROLE_OIDS: dict[str, str] = {
    "ci": ID_RSP_ROLE + ".0",
    "ciSubCa": ID_RSP_ROLE + ".0.0",
    "eum": ID_RSP_ROLE + ".0.0.0",
    "eumSubCa": ID_RSP_ROLE + ".0.0.0.0",
    "euicc": ID_RSP_ROLE + ".0.0.0.0.0",
    "dpSubCa": ID_RSP_ROLE + ".0.0.1",
    "dp-tls": ID_RSP_ROLE + ".0.0.1.0",
    "dp-auth": ID_RSP_ROLE + ".0.0.1.1",
    "dp-pb": ID_RSP_ROLE + ".0.0.1.2",
    "dsSubCa": ID_RSP_ROLE + ".0.0.2",
    "ds-tls": ID_RSP_ROLE + ".0.0.2.0",
    "ds-auth": ID_RSP_ROLE + ".0.0.2.1",
    "euicc-v2": ID_RSP_ROLE + ".1",
    "eum-v2": ID_RSP_ROLE + ".2",
    "dp-tls-v2": ID_RSP_ROLE + ".3",
    "dp-auth-v2": ID_RSP_ROLE + ".4",
    "dp-pb-v2": ID_RSP_ROLE + ".5",
    "ds-tls-v2": ID_RSP_ROLE + ".6",
    "ds-auth-v2": ID_RSP_ROLE + ".7",
}

_ROLE_BY_OID = {oid: role for role, oid in RSP_ROLE_OIDS.items()}

# The roles an RSP Server may present at each ES9+ / ES11 step.
SERVER_AUTH_ROLES = frozenset({"dp-auth", "dp-auth-v2", "ds-auth", "ds-auth-v2"})
PROFILE_BINDING_ROLES = frozenset({"dp-pb", "dp-pb-v2"})


def certificate_rsp_roles(certificate_der: bytes) -> set[str] | None:
    """Return the RSP roles named by the certificatePolicies extension.

    ``None`` means the certificate carries no certificatePolicies extension
    at all; an empty set means it carries one without any id-rspRole value.
    """
    certificate = crypto_x509.load_der_x509_certificate(bytes(certificate_der))
    try:
        extension = certificate.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
    except crypto_x509.ExtensionNotFound:
        return None
    roles: set[str] = set()
    for policy in extension.value:
        role = _ROLE_BY_OID.get(policy.policy_identifier.dotted_string)
        if role is not None:
            roles.add(role)
    return roles


def describe_rsp_roles(roles: set[str] | None) -> str:
    if roles is None:
        return "no certificatePolicies extension"
    if len(roles) == 0:
        return "certificatePolicies without an id-rspRole value"
    return ", ".join(sorted(roles))


def check_rsp_role(certificate_der: bytes, allowed: frozenset[str], label: str) -> str:
    """Return a note when the certificate's role cannot be confirmed.

    A certificate whose certificatePolicies name a role outside *allowed*
    raises ``ValueError``; one without the extension is reported in the
    returned note so a lab certificate still passes with a visible warning.
    """
    roles = certificate_rsp_roles(certificate_der)
    if roles is None:
        return f"{label} carries no certificatePolicies extension; RSP role not verified."
    if len(roles & allowed) == 0:
        raise ValueError(
            f"{label} role {describe_rsp_roles(roles)} is not one of "
            f"{', '.join(sorted(allowed))} (SGP.22 v3.1 section 4.5.2.1)."
        )
    return ""
