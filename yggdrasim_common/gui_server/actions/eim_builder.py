# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Offline Tools actions of the AddInitialEim builder and its operator store.

``tool.eim_builder.add_initial_eim`` builds an AddInitialEimRequest (SGP.32
v1.3 §5.9.4) from stored certificates and typed members and returns the APDU
sequence of the run, the eUICCMemoryReset first, without a card;
``tool.eim_builder.send`` sends the same request on a reader. The two store
actions manage the untracked certificates and saved values that the eSIM Live
verbs ADD-INITIAL-EIM and EIM-CERT-STORE share.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .registry import ActionContext, ActionField, ActionSpec, get_registry

OFFLINE_TOOLS_SUBSYSTEM = "Offline Tools"
# Shown with the one-APDU form of the request.
SINGLE_APDU_NOTE = (
    "AddInitialEim as one APDU is the request in a single STORE DATA, with an extended Lc past 255 bytes; "
    "it follows the script's first four steps, and a console that chains it sends the blocks above."
)
_SOURCE_MAX_BYTES = 1024 * 1024

_PROTOCOL_FIELDS: tuple[tuple[str, str], ...] = (
    ("eim_retrieve_https", "eimRetrieveHttps"),
    ("eim_retrieve_coaps", "eimRetrieveCoaps"),
    ("eim_inject_https", "eimInjectHttps"),
    ("eim_inject_coaps", "eimInjectCoaps"),
    ("eim_proprietary", "eimProprietary"),
)


def _line(label: str, value: Any, indent: int = 0) -> dict[str, Any]:
    return {"indent": indent, "label": label, "value": "" if value is None else str(value)}


def _certificate_lines(entry: Any, indent: int = 0) -> list[dict[str, Any]]:
    return [
        _line(entry.name, entry.summary(), indent),
        _line("Subject", entry.subject, indent + 1),
        _line("Issuer", entry.issuer, indent + 1),
        _line("Valid", f"{entry.not_before} to {entry.not_after}", indent + 1),
        _line("SubjectKeyIdentifier", entry.ski_hex or "(absent)", indent + 1),
        _line("SAN registeredID", ", ".join(entry.san_registered_ids) or "(absent)", indent + 1),
        _line("AuthorityKeyIdentifier", entry.aki_hex or "(absent)", indent + 1),
        _line("SHA-256", entry.sha256_hex, indent + 1),
    ]


def _store_snapshot() -> dict[str, Any]:
    """Certificate names and saved values the builder form offers as suggestions."""
    from SCP11.shared import eim_builder_store as store

    entries, problems = store.list_certificates()
    snapshot: dict[str, Any] = {
        "store_dir": str(store.store_dir()),
        "certificates": [entry.name for entry in entries],
        "values": {name: [] for name in store.VALUE_FIELDS},
        "last": {},
        "problems": list(problems),
    }
    try:
        snapshot["values"] = store.load_values()
        snapshot["last"] = store.load_last_build()
    except store.EimBuilderStoreError as error:
        snapshot["problems"].append(str(error))
    snapshot["configurations"] = {}
    try:
        configurations = store.load_configurations()
    except store.EimBuilderStoreError as error:
        snapshot["problems"].append(str(error))
        configurations = {}
    from SCP11.shared.eim_builder import EimBuilderError, inputs_from_configuration

    for name, values in configurations.items():
        try:
            snapshot["configurations"][name] = form_values_from_inputs(inputs_from_configuration(values))
        except EimBuilderError as error:
            snapshot["problems"].append(f"Configuration {name}: {error}")
    # The whole form of the last build or send, which a build or send form opens with.
    snapshot["last_configuration"] = {}
    try:
        remembered = store.load_last_configuration()
    except store.EimBuilderStoreError as error:
        snapshot["problems"].append(str(error))
        remembered = {}
    if remembered:
        try:
            snapshot["last_configuration"] = form_values_from_inputs(inputs_from_configuration(remembered))
        except EimBuilderError as error:
            snapshot["problems"].append(f"Last build: {error}")
    return snapshot


def form_values_from_inputs(inputs: Any) -> dict[str, Any]:
    """The build and send form's field values for one set of builder inputs."""
    protocol = set(inputs.eim_supported_protocol or ())
    values: dict[str, Any] = {
        "eim_id": inputs.eim_id,
        "eim_id_type": inputs.eim_id_type,
        "eim_fqdn": inputs.eim_fqdn,
        "counter_value": inputs.counter_value,
        "association_token": inputs.association_token,
        "eim_certificate": inputs.eim_certificate,
        "eim_key_form": inputs.eim_key_form,
        "tls_certificate": inputs.tls_certificate,
        "tls_key_form": inputs.tls_key_form,
        "euicc_ci_pk_id": inputs.euicc_ci_pk_id,
        "indirect_profile_download": inputs.indirect_profile_download,
    }
    for field_name, bit in _PROTOCOL_FIELDS:
        values[field_name] = bit in protocol
    return values


def save_form_configuration(values: dict[str, Any], inputs: Any) -> str:
    """Store the form under its Configuration name when Save is ticked; a line for the result, or empty."""
    from SCP11.shared import eim_builder_store as store
    from SCP11.shared.eim_builder import configuration_from_inputs

    if not bool(values.get("save_configuration")):
        return ""
    name = str(values.get("configuration") or "").strip()
    if not name:
        return "Save was ticked without a configuration name; nothing was saved."
    try:
        saved = store.save_configuration(name, configuration_from_inputs(inputs))
    except store.EimBuilderStoreError as error:
        return f"The configuration was not saved: {error}"
    return f"Saved the form as configuration {saved}."


def builder_inputs_from_form(values: dict[str, Any]) -> Any:
    """Turn the coerced ``BUILDER_FIELDS`` values of a form into ``BuilderInputs``.

    The Offline Tools build and the eSIM Management send share the form, so
    both read it here.
    """
    from SCP11.shared.eim_builder import BuilderInputs

    protocol = tuple(name for field_name, name in _PROTOCOL_FIELDS if bool(values.get(field_name)))
    return BuilderInputs(
        eim_id=str(values.get("eim_id") or ""),
        eim_certificate=str(values.get("eim_certificate") or ""),
        eim_key_form=str(values.get("eim_key_form") or "eimCertificate"),
        eim_id_type=str(values.get("eim_id_type") or "auto"),
        eim_fqdn=str(values.get("eim_fqdn") or ""),
        counter_value=int(values.get("counter_value") or 0),
        association_token=bool(values.get("association_token")),
        tls_certificate=str(values.get("tls_certificate") or ""),
        tls_key_form=str(values.get("tls_key_form") or "trustedCertificateTls"),
        eim_supported_protocol=protocol or None,
        euicc_ci_pk_id=str(values.get("euicc_ci_pk_id") or ""),
        indirect_profile_download=bool(values.get("indirect_profile_download")),
    )


def _dispatch_add_initial_eim(ctx: ActionContext, **values: Any) -> dict[str, Any]:
    from SCP11.shared.eim_builder import SCRIPT_CHANNEL_NOTE, build_add_initial_eim

    result = build_add_initial_eim(builder_inputs_from_form(values))
    saved_line = save_form_configuration(values, result.inputs)
    single = result.request_apdu
    return {
        "input_length": len(result.request),
        "note": (
            f"AddInitialEimRequest built and read back ({len(result.request)} bytes); nothing was sent. "
            f"The script holds {len(result.script)} APDUs, eUICCMemoryReset first; "
            "AddInitialEim send runs them on a card."
        ),
        "detail_lines": [_line(label, value, indent) for indent, label, value in result.summary_rows()],
        "validation_lines": [_line(finding.severity, finding.text) for finding in result.findings]
        + [_line("note", SCRIPT_CHANNEL_NOTE), _line("note", SINGLE_APDU_NOTE)]
        + ([_line("note", saved_line)] if saved_line else []),
        "script": {
            "title": "APDU script",
            "steps": [{"label": step.label, "apdu": step.apdu_hex} for step in result.script],
        },
        # The request in one STORE DATA, in place of its bare TLV.
        "single_apdu": {
            "title": "AddInitialEim as one APDU",
            "steps": [{"label": single.label, "apdu": single.apdu_hex}],
        },
        "request_hex": result.request.hex().upper(),
    }


def _dispatch_certificates(
    ctx: ActionContext,
    *,
    operation: Any = None,
    name: Any = None,
    certificate_file: Any = None,
    certificate_text: Any = None,
    overwrite: Any = None,
    new_name: Any = None,
) -> dict[str, Any]:
    from SCP11.shared import eim_builder_store as store
    from yggdrasim_common.secure_files import read_bounded_regular_file

    mode = str(operation or "list").strip()
    if mode == "import":
        text = str(certificate_text or "").strip()
        path_text = str(certificate_file or "").strip()
        if text and path_text:
            raise ValueError("Give a certificate file or pasted certificate text, not both.")
        if text:
            raw = text.encode("utf-8")
        elif path_text:
            path = Path(path_text).expanduser()
            try:
                raw = read_bounded_regular_file(path, _SOURCE_MAX_BYTES)
            except (OSError, ValueError) as error:
                raise ValueError(f"{path} could not be read: {error}") from error
        else:
            raise ValueError("Import needs a certificate file or pasted PEM, base64 or hex text.")
        report = store.import_certificates(raw, name=str(name or ""), overwrite=bool(overwrite))
        lines: list[dict[str, Any]] = []
        for entry in report.stored:
            lines.extend(_certificate_lines(entry))
            if entry.name in report.same_as:
                lines.append(_line("Note", f"Same certificate as the stored {report.same_as[entry.name]}.", 1))
        validation = []
        if report.private_keys_dropped:
            validation.append(
                _line(
                    "note",
                    f"{report.private_keys_dropped} private key block(s) in the source were not stored; "
                    "AddInitialEim carries public material only.",
                )
            )
        return {
            "input_length": len(raw),
            "note": f"Stored {len(report.stored)} certificate(s) in {store.certificates_dir()}.",
            "detail_lines": lines,
            "validation_lines": validation,
        }
    if mode == "rename":
        renamed, updated = store.rename_certificate(name, new_name)
        return {
            "input_length": 0,
            "note": f"Renamed {str(name or '').strip()} to {renamed}; the saved values follow.",
            "detail_lines": [_line("Configurations updated", ", ".join(updated) or "none")],
            "validation_lines": [],
        }
    if mode == "remove":
        removed = store.remove_certificate(name)
        users = store.configurations_using_certificate(removed)
        return {
            "input_length": 0,
            "note": f"Removed {removed} from {store.certificates_dir()}.",
            "detail_lines": [],
            "validation_lines": [
                _line(
                    "warning",
                    f"Configurations still naming {removed}: {', '.join(users)}; import it again or edit them.",
                )
            ]
            if users
            else [],
        }
    if mode != "list":
        raise ValueError(f"operation must be list, import, rename or remove, not {mode!r}.")
    entries, problems = store.list_certificates()
    lines = []
    for entry in entries:
        lines.extend(_certificate_lines(entry))
    return {
        "input_length": 0,
        "note": f"{len(entries)} certificate(s) in {store.certificates_dir()}.",
        "detail_lines": lines or [_line("Store", "No certificate stored yet; import one.")],
        "validation_lines": [_line("warning", problem) for problem in problems],
    }


def _dispatch_saved_values(
    ctx: ActionContext,
    *,
    operation: Any = None,
    field: Any = None,
    value: Any = None,
    new_value: Any = None,
) -> dict[str, Any]:
    from SCP11.shared import eim_builder_store as store

    mode = str(operation or "list").strip()
    note = ""
    if mode == "edit":
        field_name = str(field or "").strip()
        old_text = str(value or "").strip()
        if store.edit_value(field_name, value, new_value) is False:
            raise ValueError(f"{field_name} holds no saved value {old_text!r}.")
        note = f"Changed {field_name} {old_text!r} to {str(new_value or '').strip()!r}."
    elif mode == "forget":
        field_name = str(field or "").strip()
        if store.forget_value(field_name, value) is False:
            raise ValueError(f"{field_name} holds no saved value {str(value or '').strip()!r}.")
        note = f"Forgot {field_name} {str(value or '').strip()!r}."
    elif mode != "list":
        raise ValueError(f"operation must be list, edit or forget, not {mode!r}.")
    snapshot = _store_snapshot()
    lines: list[dict[str, Any]] = []
    stored = set(snapshot["certificates"])
    for field_name in store.VALUE_FIELDS:
        saved = snapshot["values"].get(field_name) or []
        lines.append(_line(field_name, f"{len(saved)} saved"))
        for item in saved:
            stale = field_name in store.CERTIFICATE_REFERENCE_FIELDS and item not in stored
            lines.append(_line("", f"{item} (not in the certificate store)" if stale else item, 1))
    return {
        "input_length": 0,
        "note": note or f"Saved values in {store.values_path()}.",
        "detail_lines": lines,
        "validation_lines": [_line("warning", problem) for problem in snapshot["problems"]],
        **snapshot,
    }


def _dispatch_configurations(
    ctx: ActionContext,
    *,
    operation: Any = None,
    name: Any = None,
    new_name: Any = None,
) -> dict[str, Any]:
    from SCP11.shared import eim_builder_store as store
    from SCP11.shared.eim_builder import configuration_summary

    mode = str(operation or "list").strip()
    note = ""
    if mode == "rename":
        renamed = store.rename_configuration(name, new_name)
        note = f"Renamed {str(name or '').strip()} to {renamed}."
    elif mode == "delete":
        note = f"Deleted {store.delete_configuration(name)}."
    elif mode != "list":
        raise ValueError(f"operation must be list, rename or delete, not {mode!r}.")
    configurations = store.load_configurations()
    lines: list[dict[str, Any]] = []
    for entry_name in sorted(configurations):
        values = configurations[entry_name]
        lines.append(_line(entry_name, configuration_summary(values)))
        protocol = values.get("eim_supported_protocol")
        lines.append(_line("eimIdType", values.get("eim_id_type", "auto"), 1))
        lines.append(_line("counterValue", values.get("counter_value", 0), 1))
        lines.append(_line("associationToken", "requested" if values.get("association_token") else "no", 1))
        lines.append(_line("eimSupportedProtocol", ", ".join(protocol) if protocol else "(omitted)", 1))
        lines.append(_line("euiccCiPKId", values.get("euicc_ci_pk_id") or "(omitted)", 1))
        lines.append(
            _line("indirectProfileDownload", "present" if values.get("indirect_profile_download") else "(omitted)", 1)
        )
    return {
        "input_length": 0,
        "note": note or f"{len(configurations)} configuration(s) in {store.configurations_path()}.",
        "detail_lines": lines
        or [_line("Configurations", "None saved yet; tick Save in AddInitialEim build to store one.")],
        "validation_lines": [],
        "configurations": sorted(configurations),
    }


# The EimConfigurationData form of the Offline Tools build and of the eSIM
# Management send (scp11_live.add_initial_eim).
BUILDER_FIELDS: tuple[ActionField, ...] = (
    ActionField(
        name="configuration",
        label="Configuration",
        kind="string",
        placeholder="name of a saved configuration",
        help=(
            "Picking a saved configuration fills every field below. With Save ticked, a request "
            "that builds is stored under this name, replacing a configuration of that name."
        ),
    ),
    ActionField(
        name="save_configuration",
        label="Save the form as this configuration",
        kind="bool",
        default=False,
    ),
    ActionField(
        name="eim_id",
        label="eimId",
        kind="string",
        required=True,
        placeholder="1.3.6.1.4.1.32473.999.10.124",
        help=(
            "Free text, a UTF8String of at most 128 bytes (SGP.32 v1.3 §4.3); with eimIdType auto, "
            "dotted-decimal text goes out as eimIdTypeOid. Saved for the next build."
        ),
    ),
    ActionField(
        name="eim_id_type",
        label="eimIdType",
        kind="enum",
        default="auto",
        choices=["auto", "eimIdTypeOid", "eimIdTypeFqdn", "eimIdTypeProprietary", "omit"],
        help=(
            "auto reads dotted-decimal text as an OID, a host name as an FQDN and anything "
            "else as proprietary; omit lets the eUICC store eimIdTypeProprietary."
        ),
    ),
    ActionField(
        name="eim_fqdn",
        label="eimFqdn",
        kind="string",
        placeholder="eim.example.test",
        help="FQDN of the eIM or of an intermediate server; empty leaves it out. Saved for the next build.",
    ),
    ActionField(
        name="counter_value",
        label="counterValue",
        kind="int",
        default=0,
        min_value=0,
        max_value=0x7FFFFFFF,
        help="Initial replay counter; every eUICC handles values up to 8388607 (0x7FFFFF).",
    ),
    ActionField(
        name="association_token",
        label="Request associationToken",
        kind="bool",
        default=False,
        help="Sends associationToken -1; the eUICC answers the token it assigned.",
    ),
    ActionField(
        name="eim_certificate",
        label="eIM certificate",
        kind="string",
        required=True,
        placeholder="name in the eIM certificate store",
        help="CERT.EIM.ECDSA from the store (eIM certificate store action); fills eimPublicKeyData.",
    ),
    ActionField(
        name="eim_key_form",
        label="eimPublicKeyData",
        kind="enum",
        default="eimCertificate",
        choices=["eimCertificate", "eimPublicKey"],
        help="eimCertificate sends the whole certificate, eimPublicKey only its SubjectPublicKeyInfo.",
    ),
    ActionField(
        name="tls_certificate",
        label="TLS certificate",
        kind="string",
        placeholder="name in the eIM certificate store",
        help=(
            "trustedPublicKeyDataTls: the eIM TLS certificate or a CA of its chain; "
            "empty leaves it out."
        ),
    ),
    ActionField(
        name="tls_key_form",
        label="trustedPublicKeyDataTls",
        kind="enum",
        default="trustedCertificateTls",
        choices=["trustedCertificateTls", "trustedEimPkTls"],
        help="trustedCertificateTls sends the certificate, trustedEimPkTls only its SubjectPublicKeyInfo.",
    ),
    ActionField(
        name="eim_retrieve_https",
        label="eimRetrieveHttps",
        kind="bool",
        default=True,
        help="eimSupportedProtocol bit 0. With no bit ticked the member is left out.",
    ),
    ActionField(name="eim_retrieve_coaps", label="eimRetrieveCoaps", kind="bool", default=False),
    ActionField(name="eim_inject_https", label="eimInjectHttps", kind="bool", default=False),
    ActionField(name="eim_inject_coaps", label="eimInjectCoaps", kind="bool", default=False),
    ActionField(name="eim_proprietary", label="eimProprietary", kind="bool", default=False),
    ActionField(
        name="euicc_ci_pk_id",
        label="euiccCiPKId",
        kind="hex",
        placeholder="SubjectKeyIdentifier of a CI key",
        help=(
            "An entry of euiccCiPKIdListForSigning; empty leaves the first entry to the eUICC. "
            "Saved for the next build."
        ),
    ),
    ActionField(
        name="indirect_profile_download",
        label="indirectProfileDownload",
        kind="bool",
        default=False,
        help="SGP.32 v1.3 member [9]: the eIM supports Indirect Profile download.",
    ),
)


# The send form: a reader, the builder form and the confirm checkbox. The
# Offline Tools send and the eSIM Management send (scp11_live) share it.
SEND_FIELDS: tuple[ActionField, ...] = (
    ActionField(
        name="reader",
        label="Reader",
        kind="reader",
        required=False,
        default="",
        help="PC/SC reader name (leave empty for the first reader).",
    ),
    *BUILDER_FIELDS,
    ActionField(
        name="confirm",
        label="I understand this removes the card's eIM Configuration Data and adds this eIM",
        kind="bool",
        required=False,
        default=False,
        help="Required: must be ticked for the dispatcher to run. Not stored in any environment flag.",
    ),
)
SEND_DESCRIPTION = (
    "Build ES10b.AddInitialEim (SGP.32 v1.3 §5.9.4) from the AddInitialEim builder store and "
    "send it on the reader: eUICCMemoryReset (resetEimConfigData, resetImmediateEnableConfig) first, "
    "which removes every eIM Configuration Data on the card, then the request. Gated by the confirm "
    "checkbox."
)


async def _dispatch_send(ctx: ActionContext, **values: Any) -> Any:
    # The eSIM Live console sends it; scp11_live owns that path and imports
    # this module, so the import stays inside the call.
    from .scp11_live import _dispatch_stream_add_initial_eim

    async for event in _dispatch_stream_add_initial_eim(ctx, **values):
        yield event


ADD_INITIAL_EIM_BUILD_SPEC = ActionSpec(
    id="tool.eim_builder.add_initial_eim",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="AddInitialEim build",
    description=(
        "Build an ES10b AddInitialEimRequest (SGP.32 v1.3 §5.9.4) from stored certificates "
        "and return the APDU script of the run: TERMINAL CAPABILITY, MANAGE CHANNEL, "
        "SELECT ISD-R, eUICCMemoryReset, then AddInitialEim. No card is touched; "
        "AddInitialEim send sends it."
    ),
    inputs=BUILDER_FIELDS,
    output_kind="key_value_lines",
    dispatcher=_dispatch_add_initial_eim,
    tags=("build", "eim", "sgp32", "es10"),
)


EIM_CERTIFICATES_SPEC = ActionSpec(
    id="tool.eim_builder.certificates",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="eIM certificate store",
    description=(
        "List, import, rename or remove the certificates the AddInitialEim build uses. "
        "The store is per user and never tracked."
    ),
    inputs=(
        ActionField(
            name="operation",
            label="Operation",
            kind="enum",
            default="list",
            choices=["list", "import", "rename", "remove"],
            help="Import under an existing name with Replace ticked to change a certificate's content.",
        ),
        ActionField(
            name="name",
            label="Name",
            kind="string",
            placeholder="eim-test-signing",
            help="Store name to import as, rename or remove; an import without one takes the subject CN.",
        ),
        ActionField(
            name="new_name",
            label="New name",
            kind="string",
            help="For rename: saved values and configurations naming the certificate follow it.",
        ),
        ActionField(
            name="certificate_file",
            label="Certificate file",
            kind="path",
            help="PEM (several CERTIFICATE blocks allowed), DER, base64 or hex; a private key block is dropped.",
        ),
        ActionField(
            name="certificate_text",
            label="Certificate text",
            kind="text",
            multiline=True,
            placeholder="-----BEGIN CERTIFICATE-----",
            help="Pasted PEM, base64 (standard or URL-safe) or hex of the DER, instead of a file.",
        ),
        ActionField(
            name="overwrite",
            label="Replace an entry of the same name",
            kind="bool",
            default=False,
        ),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_certificates,
    tags=("eim", "certificates", "store"),
)


EIM_SAVED_VALUES_SPEC = ActionSpec(
    id="tool.eim_builder.saved_values",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="eIM builder saved values",
    description=(
        "The eimId, eimFqdn and euiccCiPKId values and certificate names earlier builds saved; "
        "edit one in place or forget it."
    ),
    inputs=(
        ActionField(
            name="operation",
            label="Operation",
            kind="enum",
            default="list",
            choices=["list", "edit", "forget"],
        ),
        ActionField(
            name="field",
            label="Field",
            kind="enum",
            default="eim_id",
            choices=["eim_id", "eim_fqdn", "euicc_ci_pk_id", "eim_certificate", "tls_certificate"],
        ),
        ActionField(name="value", label="Value", kind="string", help="The saved value to edit or forget."),
        ActionField(name="new_value", label="New value", kind="string", help="For edit: the value to save instead."),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_saved_values,
    tags=("eim", "store"),
)


ADD_INITIAL_EIM_SEND_SPEC = ActionSpec(
    id="tool.eim_builder.send",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="AddInitialEim send",
    description=SEND_DESCRIPTION,
    inputs=SEND_FIELDS,
    output_kind="log_stream",
    dispatcher=_dispatch_send,
    requires_card=True,
    streams=True,
    tags=("eim", "sgp32", "stream", "destructive"),
)


EIM_CONFIGURATIONS_SPEC = ActionSpec(
    id="tool.eim_builder.configurations",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="eIM builder configurations",
    description=(
        "Named AddInitialEim forms: list them, rename or delete one. Save one from AddInitialEim build "
        "or send (Configuration + Save); picking it there fills the form."
    ),
    inputs=(
        ActionField(
            name="operation",
            label="Operation",
            kind="enum",
            default="list",
            choices=["list", "rename", "delete"],
        ),
        ActionField(name="name", label="Name", kind="string", help="The configuration to rename or delete."),
        ActionField(name="new_name", label="New name", kind="string", help="For rename."),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_configurations,
    tags=("eim", "store"),
)


get_registry().register(ADD_INITIAL_EIM_BUILD_SPEC)
get_registry().register(EIM_CONFIGURATIONS_SPEC)
get_registry().register(ADD_INITIAL_EIM_SEND_SPEC)
get_registry().register(EIM_CERTIFICATES_SPEC)
get_registry().register(EIM_SAVED_VALUES_SPEC)
