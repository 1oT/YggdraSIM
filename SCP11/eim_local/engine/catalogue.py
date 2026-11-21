# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Operation types of the Local eIM: parameters, SGP.32 encoding, descriptions and checks.

Each type name (ENABLE_PROFILE, ADD_EIM, ...) maps to the SGP.32 v1.3 object
it becomes: a PSMO or an eCO inside a signed eUICC Package (§2.11.1.1.2,
§2.11.1.1.3), an IpaEuiccDataRequest (§2.11.1.2) or a
ProfileDownloadTriggerRequest. Parameter values arrive as text from the
shell and the GUI and are normalised here. The checks against the eUICC
record are warnings only: the Local eIM is a test rig and queues what it is
asked to queue.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.identity import EimIdentity
from SCP11.eim_local.engine.store import EuiccRecord
from SCP11.eim_local.psmo_builders import PsmoBuildError, build_eco, build_psmo
from SCP11.shared.ber_tlv import read_ber_tlv, retag_sequence
from SCP11.shared.eim_configuration_data import (
    EIM_ID_TYPES,
    EIM_SUPPORTED_PROTOCOL_BITS,
    KEY_FORM_CERTIFICATE,
    KEY_FORM_PUBLIC_KEY,
    EimConfigurationData,
    KeyData,
    encode_eim_configuration_data,
)
from SCP11.shared.iccid import encode_ef_iccid
from SCP11.shared.profile_info import profile_info_tag_list

PACKAGE_PSMO = codec.PACKAGE_PSMO
PACKAGE_ECO = codec.PACKAGE_ECO
PACKAGE_IPA_DATA = "ipa_data"
PACKAGE_DOWNLOAD = "download"
# ES10b functions the device calls on the eUICC itself (SGP.32 v1.3 §5.9.16, §5.9.20, §5.9.21): executed by
# the direct route (DELIVER, the reader as the IPAd), never served to an IPA over ESipa.
PACKAGE_DEVICE = "device"
SIGNED_PACKAGES = (PACKAGE_PSMO, PACKAGE_ECO)

# Every IPA and eUICC data item except the Notifications ('A0') and the stored
# eUICC Package Results ('A2'), which are asked for explicitly (§2.11.1.2).
DEFAULT_IPA_DATA_TAGS = "81 83 84 A5 A6 A8 A9 BF20 BF22"
IPA_DATA_TAGS = ("A0", "81", "A2", "BF20", "BF22", "83", "84", "A5", "A6", "A8", "A9")
# The word a tags parameter takes for every tag: all IPA and eUICC data items of
# SGP.32 v1.3 §2.11.1.2 for IPA-DATA ('A0' and 'A2' included, which the eUICC
# deletes once the eIM acknowledges them), every ProfileInfo member of the
# SGP.32 version the eUICC declares for LIST-PROFILES (full_profile_info_tag_list).
TAG_LIST_ALL = "all"
# The word for the request without a tagList: the eUICC's own default set.
TAG_LIST_DEFAULT = "default"
# record.data key: the tagList of the eIM's own choosing that this eUICC answered with
# incorrectInputValues ({"tags": hex, "at": time, "operation": id}). A List profiles that names
# no tags goes without a tagList while the entry holds the list the eIM would choose.
REFUSED_TAG_LIST = "profile_info_tag_list_refused"
RECOVERY_TAGS = "A2"
CERTIFICATE_TAGS = "A5 A6 BF22 84 81 83"

FAULTS: dict[str, str] = {
    "stale-counter": "counterValue reused instead of incremented (expect replayError)",
    "wrong-eid": "eidValue of another eUICC (expect invalidEid)",
    "bad-signature": "eimSignature with one octet flipped (expect euiccPackageErrorUnsigned)",
    "wrong-token": "signed with associationToken + 1 (expect euiccPackageErrorUnsigned)",
    "unknown-eim": "eimId the eUICC does not know (expect euiccPackageErrorUnsigned)",
    # SGP.32 v1.3 §5.9.1 (p.123-124) names no range check for a package counterValue, only that it
    # exceed the stored one; a live eUICC answered replayError, the simulator counterValueOutOfRange.
    "counter-overflow": "counterValue above 0x7FFFFF (expect counterValueOutOfRange or replayError)",
}


class OperationError(ValueError):
    """An operation's parameters cannot be encoded."""


@dataclass(frozen=True)
class ParamSpec:
    name: str
    kind: str
    required: bool = False
    help: str = ""
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class OperationType:
    name: str
    verb: str
    package: str
    title: str
    params: tuple[ParamSpec, ...] = ()

    @property
    def signed(self) -> bool:
        return self.package in SIGNED_PACKAGES


# A parameter that names a saved eIM configuration of the AddInitialEim builder. It never reaches an
# operation: queueing replaces it by the fields the configuration gives (expand_eim_configuration).
KIND_CONFIGURATION = "configuration"

_ICCID = ParamSpec("iccid", "iccid", True, "ICCID of the target Profile")
_EIM_ID = ParamSpec("eim_id", "text", True, "eimId of the target eIM")
_EIM_CONFIG = ParamSpec(
    "config", KIND_CONFIGURATION, False,
    "a saved eIM configuration (AddInitialEim builder): it fills every field left empty here, the eimId included",
)
_REFRESH_FLAG = ParamSpec("refresh", "bool", False, "refreshFlag: the eUICC sends REFRESH for the switch (default on)")
_EIM_FIELDS = (
    ParamSpec("eim_fqdn", "text", False, "eimFqdn (left out when eimIdType is FQDN)"),
    ParamSpec("eim_id_type", "choice", False, "eimIdType", ("oid", "fqdn", "proprietary")),
    ParamSpec("counter_value", "int", False, "initial counterValue"),
    ParamSpec("certificate", "key", False, "eIM signing certificate: hex DER, or a name in the AddInitialEim builder store"),
    ParamSpec("public_key", "hex", False, "eIM public key as a DER SubjectPublicKeyInfo (instead of certificate)"),
    ParamSpec("tls_certificate", "key", False, "trustedPublicKeyDataTls certificate: hex DER or a stored name"),
    ParamSpec("protocols", "text", False, "eimSupportedProtocol bits, comma separated"),
    ParamSpec("ci_pkid", "hex", False, "euiccCiPKId"),
    ParamSpec("indirect", "bool", False, "indirectProfileDownload"),
)

OPERATION_TYPES: dict[str, OperationType] = {
    entry.name: entry
    for entry in (
        OperationType(
            "PROFILE_DOWNLOAD_TRIGGER", "DOWNLOAD", PACKAGE_DOWNLOAD, "Download profile",
            (
                ParamSpec("activation_code", "text", False, "activation code, e.g. 1$smdpp.example.test$MATCHING-ID"),
                ParamSpec("contact_default_smdp", "bool", False, "contact the default SM-DP+ instead"),
                ParamSpec("contact_smds", "bool", False,
                          "retrieve Event Records from an SM-DS instead; with indirect the eIM does it over ES11' "
                          "and queues a download per record (SGP.32 v1.3 §3.9.2.2)"),
                ParamSpec("smds_address", "text", False, "SM-DS address for contact_smds"),
                ParamSpec("indirect", "bool", False,
                          "keep the download data at the eIM and serve an empty trigger: the IPA downloads "
                          "through the eIM (SGP.32 v1.3 §3.2.3.2)"),
                ParamSpec("confirmation_code", "text", False,
                          "Confirmation Code of the order; when the SM-DP+ requires one, the eIM hands the IPA "
                          "its hash in ESipa.AuthenticateClient (SGP.32 v1.3 §5.14.3)"),
                ParamSpec("event_id", "text", False,
                          "set by the eIM on a download queued from an SM-DS Event Record: the EventID, its "
                          "Matching ID (SGP.22 v3.1 §3.1.3)"),
                ParamSpec("smds_oid", "text", False,
                          "set by the eIM with event_id: the OID of the SM-DS that provided the EventID"),
            ),
        ),
        OperationType(
            "ENABLE_PROFILE", "ENABLE", PACKAGE_PSMO, "Enable profile",
            (_ICCID, ParamSpec("rollback", "bool", False, "rollbackFlag: the IPA may roll back")),
        ),
        OperationType("DISABLE_PROFILE", "DISABLE", PACKAGE_PSMO, "Disable profile", (_ICCID,)),
        OperationType("DELETE_PROFILE", "DELETE", PACKAGE_PSMO, "Delete profile", (_ICCID,)),
        OperationType(
            "PROFILE_INFO_LIST", "LIST-PROFILES", PACKAGE_PSMO, "List profiles",
            (
                ParamSpec("tags", "hex", False,
                          "tagList: all asks for every ProfileInfo member of the SGP.32 version the eUICC "
                          "declares (the default, until the eUICC refuses that list); default sends none, for "
                          "the eUICC's own default set; or tags, e.g. 5A 9F70 92 9F26"),
                ParamSpec("iccid", "iccid", False, "search criteria: one ICCID"),
            ),
        ),
        OperationType("GET_RAT", "GET-RAT", PACKAGE_PSMO, "Get Rules Authorisation Table"),
        OperationType(
            "CONFIGURE_IMMEDIATE_ENABLE", "IMMEDIATE-ENABLE", PACKAGE_PSMO, "Configure immediate profile enabling",
            (
                ParamSpec("enabled", "bool", True, "immediateEnableFlag on or off"),
                ParamSpec("default_smdp_address", "text", False, "defaultSmdpAddress"),
                ParamSpec("default_smdp_oid", "text", False, "defaultSmdpOid"),
            ),
        ),
        OperationType("SET_FALLBACK_ATTRIBUTE", "FALLBACK", PACKAGE_PSMO, "Set fallback profile", (_ICCID,)),
        OperationType("UNSET_FALLBACK_ATTRIBUTE", "UNSET-FALLBACK", PACKAGE_PSMO, "Unset fallback profile"),
        OperationType(
            "SET_DEFAULT_DP_ADDRESS", "DEFAULT-SMDP", PACKAGE_PSMO, "Set default SM-DP+ address",
            (ParamSpec("address", "text", True, "default SM-DP+ address (FQDN)"),),
        ),
        OperationType(
            "ADD_EIM", "ADD-EIM", PACKAGE_ECO, "Add eIM",
            (_EIM_CONFIG, _EIM_ID, *_EIM_FIELDS,
             ParamSpec("association_token", "bool", False, "ask the eUICC for an association token")),
        ),
        OperationType("UPDATE_EIM", "UPDATE-EIM", PACKAGE_ECO, "Update eIM", (_EIM_ID, *_EIM_FIELDS)),
        OperationType("DELETE_EIM", "DELETE-EIM", PACKAGE_ECO, "Delete eIM", (_EIM_ID,)),
        OperationType("LIST_EIM", "LIST-EIM", PACKAGE_ECO, "List eIMs"),
        OperationType(
            "IPA_EUICC_DATA", "IPA-DATA", PACKAGE_IPA_DATA, "Get eUICC data",
            (
                ParamSpec("tags", "hex", False,
                          f"tagList (default {DEFAULT_IPA_DATA_TAGS}); all asks for every tag of SGP.32 v1.3 "
                          "§2.11.1.2, the Notifications 'A0' and the stored eUICC Package Results 'A2' included, "
                          "which the eUICC deletes once the eIM has acknowledged them"),
                ParamSpec("ci_pkid", "hex", False, "euiccCiPKIdentifierToBeUsed"),
                ParamSpec("notification_seq", "int", False, "searchCriteriaNotification seqNumber"),
                ParamSpec("result_seq", "int", False, "searchCriteriaEuiccPackageResult seqNumber"),
            ),
        ),
        OperationType(
            "PSMO_RAW", "RAW-PSMO", PACKAGE_PSMO, "Raw PSMO package",
            (ParamSpec("items", "hex", True, "psmoList contents: one or more Psmo TLVs"),),
        ),
        OperationType(
            "ECO_RAW", "RAW-ECO", PACKAGE_ECO, "Raw eCO package",
            (ParamSpec("items", "hex", True, "ecoList contents: one or more Eco TLVs"),),
        ),
        OperationType("PROFILE_ROLLBACK", "ROLLBACK", PACKAGE_DEVICE, "Profile rollback (device)", (_REFRESH_FLAG,)),
        OperationType("EXECUTE_FALLBACK", "EXECUTE-FALLBACK", PACKAGE_DEVICE, "Execute fallback mechanism (device)",
                      (_REFRESH_FLAG,)),
        OperationType("RETURN_FROM_FALLBACK", "RETURN-FALLBACK", PACKAGE_DEVICE, "Return from fallback (device)",
                      (_REFRESH_FLAG,)),
    )
}

DEVICE_FUNCTION_TAGS: dict[str, bytes] = {
    "PROFILE_ROLLBACK": codec.TAG_PROFILE_ROLLBACK,
    "EXECUTE_FALLBACK": codec.TAG_EXECUTE_FALLBACK,
    "RETURN_FROM_FALLBACK": codec.TAG_RETURN_FROM_FALLBACK,
}

VERB_TYPES: dict[str, str] = {entry.verb: entry.name for entry in OPERATION_TYPES.values()}


def operation_type(name: str) -> OperationType:
    key = str(name or "").strip().upper().replace("-", "_")
    if key in OPERATION_TYPES:
        return OPERATION_TYPES[key]
    by_verb = VERB_TYPES.get(str(name or "").strip().upper())
    if by_verb is not None:
        return OPERATION_TYPES[by_verb]
    raise OperationError(f"Unknown operation type {name!r}. Known: {', '.join(sorted(OPERATION_TYPES))}.")


# ---------------------------------------------------------------------------
# Parameter normalisation
# ---------------------------------------------------------------------------

_TRUE = ("1", "true", "yes", "on", "y")
_FALSE = ("0", "false", "no", "off", "n", "")


def parse_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value if value is not None else "").strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise OperationError(f"{name} takes on/off, got {value!r}.")


def parse_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise OperationError(f"{name} takes a number, got {value!r}.")
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError as error:
        raise OperationError(f"{name} takes a number, got {value!r}.") from error


def parse_hex(value: Any, name: str) -> str:
    text = "".join(str(value or "").split()).upper()
    if text.startswith("0X"):
        text = text[2:]
    if len(text) % 2 != 0 or any(character not in "0123456789ABCDEF" for character in text):
        raise OperationError(f"{name} takes hex octets, got {value!r}.")
    return text


def parse_iccid(value: Any, name: str = "iccid") -> str:
    digits = "".join(str(value or "").split()).upper().rstrip("F")
    if not 18 <= len(digits) <= 20 or any(character not in "0123456789" for character in digits):
        raise OperationError(f"{name} takes 18-20 ICCID digits, got {value!r}.")
    return digits


def normalize_params(kind: OperationType, values: dict[str, Any], *, partial: bool = False) -> dict[str, Any]:
    """Return typed parameters; unknown names and missing required ones raise OperationError.

    With *partial* the required check is skipped (used when editing): an empty
    value removes a parameter.
    """
    known = {spec.name: spec for spec in kind.params}
    result: dict[str, Any] = {}
    for name, raw in values.items():
        key = str(name).strip().lower().replace("-", "_")
        spec = known.get(key)
        if spec is None:
            raise OperationError(f"{kind.name} has no parameter {name!r}. It takes: {', '.join(known) or 'none'}.")
        if raw is None or (isinstance(raw, str) and len(raw.strip()) == 0 and spec.kind != "bool"):
            if partial:
                result[key] = None
            continue
        if spec.kind == "bool":
            result[key] = parse_bool(raw, key)
        elif spec.kind == "int":
            result[key] = parse_int(raw, key)
        elif spec.kind == "hex":
            if key == "tags" and str(raw).strip().lower() in (TAG_LIST_ALL, TAG_LIST_DEFAULT):
                result[key] = str(raw).strip().lower()
            else:
                result[key] = parse_hex(raw, key)
        elif spec.kind == "iccid":
            result[key] = parse_iccid(raw, key)
        elif spec.kind == "choice":
            text = str(raw).strip().lower()
            if text not in spec.choices:
                raise OperationError(f"{key} is one of {', '.join(spec.choices)}, got {raw!r}.")
            result[key] = text
        else:
            result[key] = str(raw).strip()
    if not partial:
        missing = [spec.name for spec in kind.params if spec.required and spec.name not in result]
        if missing:
            raise OperationError(f"{kind.name} needs {', '.join(missing)}.")
    return result


def configuration_params(entry: EimConfigurationData) -> dict[str, Any]:
    """The eIM fields of an operation that encode *entry* again (``_configuration`` is the way back)."""
    params: dict[str, Any] = {"eim_id": entry.eim_id}
    if entry.eim_fqdn:
        params["eim_fqdn"] = entry.eim_fqdn
    if entry.eim_id_type is not None:
        params["eim_id_type"] = {1: "oid", 2: "fqdn", 3: "proprietary"}[int(entry.eim_id_type)]
    if entry.counter_value is not None:
        params["counter_value"] = int(entry.counter_value)
    key = entry.eim_public_key_data
    if key is not None:
        params["certificate" if key.form == KEY_FORM_CERTIFICATE else "public_key"] = bytes(key.der).hex().upper()
    tls = entry.trusted_public_key_data_tls
    if tls is not None:
        # One field for both forms: _key_data tells a certificate from a SubjectPublicKeyInfo by its DER.
        params["tls_certificate"] = bytes(tls.der).hex().upper()
    if entry.eim_supported_protocol:
        params["protocols"] = ",".join(entry.eim_supported_protocol)
    if entry.euicc_ci_pk_id:
        params["ci_pkid"] = bytes(entry.euicc_ci_pk_id).hex().upper()
    if entry.indirect_profile_download:
        params["indirect"] = True
    if entry.association_token is not None:
        params["association_token"] = True
    return params


def expand_eim_configuration(
    kind: OperationType, values: dict[str, Any], *, directory: Any = None, replace: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Replace ``config`` by the fields of the saved eIM configuration it names; return them with any warnings.

    The entry is built the way AddInitialEim builds it for the same
    configuration, so an eIM added by an eCO carries what the builder would
    have put on the card. A field given beside ``config`` wins over the
    configuration's. The name itself is not kept: an operation holds explicit
    fields, so renaming or deleting the configuration later changes nothing
    that is queued. With *replace* (an edit of an operation that has fields
    already) every field the configuration leaves out comes back as None, so
    the operation ends up with the configuration's entry and nothing older.
    """
    if not any(spec.kind == KIND_CONFIGURATION for spec in kind.params):
        return dict(values), []
    given = {str(name).strip().lower().replace("-", "_"): raw for name, raw in values.items()}
    name = str(given.pop("config", "") or "").strip()
    if len(name) == 0:
        return given, []
    from SCP11.shared import eim_builder, eim_builder_store

    try:
        configurations = eim_builder_store.load_configurations(directory)
    except eim_builder_store.EimBuilderStoreError as error:
        raise OperationError(f"The saved eIM configurations do not read: {error}") from error
    chosen = configurations.get(name)
    if chosen is None:
        saved = ", ".join(sorted(configurations)) or "none"
        raise OperationError(
            f"No saved eIM configuration {name!r} (saved: {saved}). Offline Tools > AddInitialEim saves one, "
            "and so does ADD-INITIAL-EIM in the eSIM Management console."
        )
    try:
        built = eim_builder.build_add_initial_eim(
            eim_builder.inputs_from_configuration(chosen), directory=directory, remember=False,
        )
    except (eim_builder.EimBuilderError, eim_builder_store.EimBuilderStoreError) as error:
        raise OperationError(f"eIM configuration {name!r}: {error}") from error
    known = {spec.name for spec in kind.params}
    filled = {key: value for key, value in configuration_params(built.entry).items() if key in known}
    explicit = {key: raw for key, raw in given.items()
                if raw is not None and not (isinstance(raw, str) and len(raw.strip()) == 0)}
    # The two forms of eimPublicKeyData exclude each other: the one given by hand is the one kept.
    if "certificate" in explicit:
        filled.pop("public_key", None)
    if "public_key" in explicit:
        filled.pop("certificate", None)
    if replace:
        for spec in kind.params:
            if spec.kind != KIND_CONFIGURATION:
                filled.setdefault(spec.name, None)
    filled.update(explicit)
    notes = [f"eIM configuration {name}: {finding.text}" for finding in built.findings
             if finding.severity == "warning"]
    return filled, notes


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def _key_data(value: str, name: str) -> KeyData:
    """Return KeyData from hex DER (certificate or SubjectPublicKeyInfo) or a builder-store name."""
    text = str(value or "").strip()
    try:
        der = bytes.fromhex("".join(text.split()))
    except ValueError:
        der = b""
    if len(der) == 0:
        from SCP11.shared.eim_builder_store import EimBuilderStoreError, read_certificate

        try:
            return KeyData(form=KEY_FORM_CERTIFICATE, der=read_certificate(text).der)
        except EimBuilderStoreError as error:
            raise OperationError(f"{name}: {error}") from error
    try:
        x509.load_der_x509_certificate(der)
    except ValueError:
        try:
            serialization.load_der_public_key(der)
        except (ValueError, TypeError) as error:
            raise OperationError(f"{name} is neither a DER certificate nor a DER SubjectPublicKeyInfo.") from error
        return KeyData(form=KEY_FORM_PUBLIC_KEY, der=der)
    return KeyData(form=KEY_FORM_CERTIFICATE, der=der)


def _protocols(value: str) -> tuple[str, ...]:
    names = tuple(part.strip() for part in str(value or "").split(",") if len(part.strip()) > 0)
    unknown = [name for name in names if name not in EIM_SUPPORTED_PROTOCOL_BITS]
    if unknown:
        raise OperationError(
            f"Unknown eimSupportedProtocol {', '.join(unknown)}; known: {', '.join(EIM_SUPPORTED_PROTOCOL_BITS)}."
        )
    return names


def _configuration(params: dict[str, Any], *, adding: bool) -> EimConfigurationData:
    id_type_name = params.get("eim_id_type")
    id_type = {"oid": 1, "fqdn": 2, "proprietary": 3}.get(id_type_name) if id_type_name else None
    key: KeyData | None = None
    if params.get("certificate"):
        key = _key_data(params["certificate"], "certificate")
    elif params.get("public_key"):
        key = _key_data(params["public_key"], "public_key")
    tls = _key_data(params["tls_certificate"], "tls_certificate") if params.get("tls_certificate") else None
    protocols = _protocols(params["protocols"]) if params.get("protocols") else None
    ci_pkid = bytes.fromhex(params["ci_pkid"]) if params.get("ci_pkid") else None
    counter = params.get("counter_value")
    if adding and counter is None:
        counter = 0
    token = -1 if adding and params.get("association_token") else None
    return EimConfigurationData(
        eim_id=params["eim_id"],
        eim_fqdn=params.get("eim_fqdn") or None,
        eim_id_type=id_type,
        counter_value=counter,
        association_token=token,
        eim_public_key_data=key,
        trusted_public_key_data_tls=tls,
        eim_supported_protocol=protocols,
        euicc_ci_pk_id=ci_pkid,
        indirect_profile_download=bool(params.get("indirect", False)),
    )


def record_iot_versions(record: EuiccRecord | None) -> tuple[tuple[int, int, int], ...]:
    """The SGP.32 versions the eUICC of *record* declares in the EUICCInfo2 on record; empty without one."""
    from SCP03.logic.euicc_info2 import declared_iot_versions

    data = getattr(record, "data", None) or {}
    try:
        info2 = bytes.fromhex(str(data.get("euicc_info2_hex") or ""))
    except ValueError:
        return ()
    return declared_iot_versions(info2)


def full_profile_info_tag_list(record: EuiccRecord | None) -> str:
    """The tagList hex that names every ProfileInfo member the eUICC of *record* defines."""
    return profile_info_tag_list(record_iot_versions(record))


def refused_tag_list(record: EuiccRecord | None) -> str:
    """The tagList hex this eUICC refused when the eIM chose it; empty when it refused none."""
    entry = (getattr(record, "data", None) or {}).get(REFUSED_TAG_LIST)
    return str(entry.get("tags") or "") if isinstance(entry, dict) else ""


def profile_list_tag_list(params: dict[str, Any], record: EuiccRecord | None = None) -> str:
    """The tagList hex a List profiles carries for the eUICC of *record*; empty sends none.

    Without a tagList the eUICC answers a default set (SGP.32 v1.3 §2.11.1.1,
    p.35) that leaves out the Profile Policy Rules, the Profile Owner and the
    Notification configuration, so the eIM names every member of the
    ProfileInfo the eUICC's version defines. ``all`` always sends that list;
    no ``tags`` sends it until this eUICC has answered it with
    incorrectInputValues, and none from then on; ``default`` sends none; any
    other value goes as given.
    """
    tags = str(params.get("tags") or "")
    if tags == TAG_LIST_DEFAULT:
        return ""
    if tags not in ("", TAG_LIST_ALL):
        return tags
    full = full_profile_info_tag_list(record)
    if tags == "" and refused_tag_list(record) == full:
        return ""
    return full


def _list_profile_info(params: dict[str, Any], record: EuiccRecord | None = None) -> bytes:
    # ProfileInfoListRequest [45]: searchCriteria [0] is a CHOICE, so explicit 'A0'.
    body = b""
    if params.get("iccid"):
        body += codec.tlv(b"\xA0", codec.tlv(b"\x5A", encode_ef_iccid(params["iccid"])))
    tags = profile_list_tag_list(params, record)
    if len(tags) > 0:
        body += codec.tlv(b"\x5C", bytes.fromhex(tags))
    return codec.tlv(b"\xBF\x2D", body)


def ipa_data_tag_list(params: dict[str, Any]) -> str:
    """The tagList hex an IPA-DATA operation asks for: its own tags, every tag for ``all``, else the default."""
    tags = str(params.get("tags") or DEFAULT_IPA_DATA_TAGS)
    if tags == TAG_LIST_DEFAULT:
        return DEFAULT_IPA_DATA_TAGS
    return " ".join(IPA_DATA_TAGS) if tags == TAG_LIST_ALL else tags


_PSMO_SPECS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "ENABLE_PROFILE": lambda p: {"operation": "enable", "iccid": p["iccid"], "rollback": bool(p.get("rollback"))},
    "DISABLE_PROFILE": lambda p: {"operation": "disable", "iccid": p["iccid"]},
    "DELETE_PROFILE": lambda p: {"operation": "delete", "iccid": p["iccid"]},
    "GET_RAT": lambda p: {"operation": "get_rat"},
    "CONFIGURE_IMMEDIATE_ENABLE": lambda p: {
        "operation": "configure_immediate_enable",
        "immediate_enable_flag": bool(p.get("enabled")),
        "default_smdp_address": p.get("default_smdp_address") or "",
        "default_smdp_oid": p.get("default_smdp_oid") or "",
    },
    "SET_FALLBACK_ATTRIBUTE": lambda p: {"operation": "set_fallback_attribute", "iccid": p["iccid"]},
    "UNSET_FALLBACK_ATTRIBUTE": lambda p: {"operation": "unset_fallback_attribute"},
    "SET_DEFAULT_DP_ADDRESS": lambda p: {"operation": "set_default_dp_address", "default_dp_address": p["address"]},
}


def build_items(
    kind: OperationType, params: dict[str, Any], raw_items: str = "", *, record: EuiccRecord | None = None,
) -> bytes:
    """Return the psmoList / ecoList contents of a signed operation; *raw_items* replaces them.

    *record* is the eUICC the items are for: the tagList of a List profiles
    that names no tags depends on it (profile_list_tag_list).
    """
    if not kind.signed:
        raise OperationError(f"{kind.name} is not carried in a signed eUICC Package.")
    if len(raw_items) > 0:
        return bytes.fromhex(raw_items)
    try:
        if kind.name in ("PSMO_RAW", "ECO_RAW"):
            return bytes.fromhex(params["items"])
        if kind.name == "PROFILE_INFO_LIST":
            return _list_profile_info(params, record)
        if kind.name in _PSMO_SPECS:
            return build_psmo(_PSMO_SPECS[kind.name](params))
        if kind.name == "ADD_EIM":
            return retag_sequence(b"\xA8", encode_eim_configuration_data(_configuration(params, adding=True)))
        if kind.name == "UPDATE_EIM":
            return retag_sequence(b"\xAA", encode_eim_configuration_data(_configuration(params, adding=False)))
        if kind.name == "DELETE_EIM":
            return build_eco({"operation": "delete_eim", "eim_id": params["eim_id"]})
        if kind.name == "LIST_EIM":
            return build_eco({"operation": "list_eim"})
    except (PsmoBuildError, ValueError) as error:
        if isinstance(error, OperationError):
            raise
        raise OperationError(f"{kind.name}: {error}") from error
    raise OperationError(f"No encoder for {kind.name}.")


def trigger_served_empty(operation: Any, features: frozenset[str]) -> bool:
    """Whether the download trigger of *operation* goes without profileDownloadData: the eIM keeps the data
    (``indirect``) and the IPA declares eimDownloadDataHandling, the "If and only if" of SGP.32 v1.3
    §2.11.1.3 (p.38). Every other IPA gets the Activation Code and may still download through the eIM."""
    params = getattr(operation, "params", operation) or {}
    return bool(params.get("indirect")) and "eimDownloadDataHandling" in features


def build_unsigned_request(
    kind: OperationType,
    params: dict[str, Any],
    transaction_id: bytes,
    *,
    ipa_features: frozenset[str] = frozenset({"eimDownloadDataHandling"}),
) -> bytes:
    """Return the IpaEuiccDataRequest or ProfileDownloadTriggerRequest of an unsigned operation.

    *ipa_features* are the IPA's declared capabilities; an ``indirect`` trigger is
    served empty only when they include eimDownloadDataHandling.
    """
    if kind.package == PACKAGE_IPA_DATA:
        tags = bytes.fromhex(parse_hex(ipa_data_tag_list(params), "tags"))
        return codec.build_ipa_euicc_data_request(
            tag_list=tags,
            transaction_id=transaction_id,
            euicc_ci_pkid=bytes.fromhex(params["ci_pkid"]) if params.get("ci_pkid") else b"",
            notification_seq_number=params.get("notification_seq"),
            result_seq_number=params.get("result_seq"),
        )
    if kind.package == PACKAGE_DOWNLOAD:
        code = activation_code_text(params.get("activation_code"))
        default = bool(params.get("contact_default_smdp"))
        smds = bool(params.get("contact_smds"))
        if len(code) == 0 and not default and not smds:
            raise OperationError("A download needs activation_code, contact_default_smdp or contact_smds.")
        if trigger_served_empty(params, ipa_features):
            # No profileDownloadData: the eIM keeps it and relays the download
            # (SGP.32 v1.3 §2.11.1.3, §3.2.3.2).
            return codec.build_profile_download_trigger_request(transaction_id=transaction_id)
        try:
            return codec.build_profile_download_trigger_request(
                activation_code=code,
                contact_default_smdp=default,
                contact_smds=smds,
                smds_address=str(params.get("smds_address") or ""),
                transaction_id=transaction_id,
            )
        except ValueError as error:
            raise OperationError(str(error)) from error
    if kind.package == PACKAGE_DEVICE:
        return codec.build_device_request(DEVICE_FUNCTION_TAGS[kind.name], refresh=device_refresh_flag(params))
    raise OperationError(f"{kind.name} is carried in a signed eUICC Package.")


def device_refresh_flag(params: dict[str, Any]) -> bool:
    """The refreshFlag of a device-side function: on unless the operation says ``refresh=off``."""
    return True if params.get("refresh") is None else bool(params["refresh"])


def preview_bytes(
    kind: OperationType, params: dict[str, Any], raw_items: str = "", *, record: EuiccRecord | None = None,
) -> bytes:
    """Return what is fixed at submit: the inner items, or the whole unsigned request."""
    if kind.signed:
        return build_items(kind, params, raw_items, record=record)
    return build_unsigned_request(kind, params, b"")


def item_tags(items: bytes) -> list[str]:
    tags: list[str] = []
    offset = 0
    while offset < len(items):
        try:
            tag, _value, _raw, offset = read_ber_tlv(items, offset)
        except ValueError:
            tags.append("malformed")
            break
        tags.append(tag.hex().upper())
    return tags


# ---------------------------------------------------------------------------
# Descriptions and checks
# ---------------------------------------------------------------------------


def describe(kind: OperationType, params: dict[str, Any]) -> str:
    """One line in the portal's wording."""
    iccid = params.get("iccid")
    if kind.name == "ENABLE_PROFILE":
        return f"Enable {iccid}" + (" with rollback" if params.get("rollback") else "")
    if kind.name == "DISABLE_PROFILE":
        return f"Disable {iccid}"
    if kind.name == "DELETE_PROFILE":
        return f"Delete {iccid}"
    if kind.name == "SET_FALLBACK_ATTRIBUTE":
        return f"Set {iccid} as fallback profile"
    if kind.name == "CONFIGURE_IMMEDIATE_ENABLE":
        return "Configure immediate profile enabling: " + ("on" if params.get("enabled") else "off")
    if kind.name == "SET_DEFAULT_DP_ADDRESS":
        return f"Set default SM-DP+ address {params.get('address', '')}"
    if kind.name in ("ADD_EIM", "UPDATE_EIM", "DELETE_EIM"):
        return f"{kind.title} {params.get('eim_id', '')}"
    if kind.name == "PROFILE_DOWNLOAD_TRIGGER":
        route = ", indirect" if params.get("indirect") else ""
        if params.get("event_id"):
            return f"Download profile (event {params['event_id']}, {params.get('activation_code', '')}{route})"
        if params.get("activation_code"):
            return f"Download profile ({params['activation_code']}{route})"
        if params.get("contact_smds"):
            return "Download profile (contact SM-DS)"
        return f"Download profile (contact default SM-DP+{route})"
    if kind.package == PACKAGE_DEVICE:
        return f"{kind.title}, refreshFlag {'on' if device_refresh_flag(params) else 'off'}"
    return kind.title


def _profile(record: EuiccRecord, iccid: str) -> dict[str, Any] | None:
    for profile in record.profiles:
        if str(profile.get("iccid", "")).upper().rstrip("F") == iccid:
            return profile
    return None


def package_rule_warnings(kind: OperationType, items: bytes) -> list[str]:
    """SGP.32 v1.3 §2.11.1.1.3 (p.35-36) rules, read from the items as built."""
    if kind.package != PACKAGE_PSMO:
        return []
    tags = item_tags(items)
    warnings: list[str] = []
    if tags.count("A3") > 1:
        warnings.append("more than one enable in one eUICC Package (SGP.32 v1.3 §2.11.1.1.3)")
    if tags.count("A4") > 1:
        warnings.append("more than one disable in one eUICC Package (SGP.32 v1.3 §2.11.1.1.3)")
    seen_change = False
    for tag in tags:
        if tag in ("A3", "A4", "A5"):
            seen_change = True
        elif tag == "BF2D" and seen_change:
            warnings.append("listProfileInfo after an enable, disable or delete (SGP.32 v1.3 §2.11.1.1.3)")
            break
    if "malformed" in tags:
        warnings.append("the items do not parse as BER-TLV")
    return warnings


def precondition_warnings(
    kind: OperationType,
    params: dict[str, Any],
    record: EuiccRecord | None,
    identity: EimIdentity | None,
) -> list[str]:
    """What the eUICC record says will probably fail; never a refusal."""
    warnings: list[str] = []
    if record is None:
        return ["the eUICC is not registered yet; it is registered on submit"]
    iccid = params.get("iccid")
    profiles_known = "profiles" in record.data
    if kind.name in ("ENABLE_PROFILE", "DISABLE_PROFILE", "DELETE_PROFILE", "SET_FALLBACK_ATTRIBUTE") and iccid:
        if not profiles_known:
            warnings.append("no profile list on the record (run LIST-PROFILES or EUICC READ); not checked")
        else:
            profile = _profile(record, iccid)
            state = (profile or {}).get("state")
            if profile is None:
                warnings.append(f"{iccid} is not in the record's profile list")
            elif kind.name == "ENABLE_PROFILE" and state == "enabled":
                warnings.append(f"{iccid} is already enabled (expect profileNotInDisabledState)")
            elif kind.name == "DISABLE_PROFILE" and state == "disabled":
                warnings.append(f"{iccid} is already disabled (expect profileNotInEnabledState)")
            elif kind.name == "DELETE_PROFILE" and state == "enabled":
                warnings.append(f"{iccid} is enabled (expect profileNotInDisabledState)")
            elif kind.name == "SET_FALLBACK_ATTRIBUTE" and profile.get("fallback_allowed") is False:
                warnings.append(f"{iccid} does not allow fallback (expect fallbackNotAllowed)")
    if kind.name == "UNSET_FALLBACK_ATTRIBUTE" and profiles_known:
        if not any(profile.get("fallback") for profile in record.profiles):
            warnings.append("no profile carries the fallback attribute (expect noFallbackAttribute)")
    eim_ids = [str(entry.get("eim_id", "")) for entry in record.eims]
    eims_known = "eims" in record.data
    if kind.name == "ADD_EIM" and eims_known and params.get("eim_id") in eim_ids:
        warnings.append(f"{params['eim_id']} is already associated (expect associatedEimAlreadyExists)")
    if kind.name in ("DELETE_EIM", "UPDATE_EIM") and eims_known and params.get("eim_id") not in eim_ids:
        warnings.append(f"{params.get('eim_id')} is not in the record's eIM list (expect eimNotFound)")
    if kind.name == "DELETE_EIM" and identity is not None and params.get("eim_id") == identity.eim_id:
        warnings.append("this deletes the Local eIM from the card; it can sign nothing for it afterwards")
    if kind.name == "ADD_EIM" and not (params.get("certificate") or params.get("public_key")):
        warnings.append("addEim without eimPublicKeyData (SGP.32 v1.3 §2.11.1.1.2 makes it mandatory)")
    if kind.name == "PROFILE_DOWNLOAD_TRIGGER" and params.get("activation_code"):
        parts = activation_code_text(params["activation_code"]).split("$")
        if len(parts) < 3 or parts[0] != "1":
            warnings.append("the activation code does not read as 1$<SM-DP+ address>$<matching id>")
    if kind.name == "PROFILE_DOWNLOAD_TRIGGER" and params.get("indirect"):
        features = ipa_features(record)
        if features is not None and 1 not in features:
            warnings.append("the IPA capabilities on record lack indirectRspServerCommunication")
        if features is not None and 2 not in features:
            warnings.append("the IPA capabilities on record lack eimDownloadDataHandling, so the trigger carries the "
                            "Activation Code (SGP.32 v1.3 §2.11.1.3) and the IPA chooses whether the eIM relays it")
        if params.get("contact_default_smdp") and (record is None or not record.data.get("default_smdp_address")):
            warnings.append("no default SM-DP+ address on record for the eIM to use (queue IPA-DATA first)")
    if kind.signed and identity is not None and record.data.get("associated") is False:
        warnings.append("the record says the Local eIM is not associated with this card (run ASSOCIATE)")
    if kind.name == "PROFILE_INFO_LIST" and not params.get("tags"):
        refused = refused_tag_list(record)
        if len(refused) > 0 and refused == full_profile_info_tag_list(record):
            entry = record.data.get(REFUSED_TAG_LIST) or {}
            warnings.append(
                f"sent without a tagList: this eUICC answered the tagList {refused} with incorrectInputValues "
                f"(operation {entry.get('operation', '?')}); tags=all sends it again"
            )
    return warnings


def activation_code_text(value: object) -> str:
    """The Activation Code proper: the 'LPA:' prefix belongs to its QR code form only (SGP.22 v3.1 §4.1)."""
    text = str(value or "").strip()
    return text[4:].strip() if text[:4].upper() == "LPA:" else text


def ipa_features(record: EuiccRecord | None) -> set[int] | None:
    """The ipaFeatures bits of the IpaCapabilities on record (SGP.32 v1.3), or None when none was read."""
    if record is None:
        return None
    text = str(record.data.get("ipa_capabilities_hex", "") or "")
    if not text:
        return None
    from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

    try:
        data = bytes.fromhex(text)
        if data[:1] == b"\xA8":
            data = read_single_ber_tlv(data)[1]
        offset = 0
        while offset < len(data):
            tag, value, _raw, offset = read_ber_tlv(data, offset)
            if tag == b"\x80" and len(value) >= 1:
                bits = value[1:]
                return {index for index in range(len(bits) * 8) if bits[index // 8] & (0x80 >> (index % 8))}
    except (ValueError, IndexError):
        return None
    return None


def fault_warning(fault: str) -> str:
    if len(fault) == 0:
        return ""
    if fault not in FAULTS:
        raise OperationError(f"Unknown fault {fault!r}; known: {', '.join(FAULTS)}.")
    return f"fault injected: {FAULTS[fault]}"


def eim_id_type_code(name: str | None) -> int | None:
    if name is None:
        return None
    return {"oid": EIM_ID_TYPES["eimIdTypeOid"], "fqdn": EIM_ID_TYPES["eimIdTypeFqdn"],
            "proprietary": EIM_ID_TYPES["eimIdTypeProprietary"]}.get(name)
