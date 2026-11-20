# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""AddInitialEim builder shared by the Offline Tools form and the eSIM Live wizard.

``BuilderInputs`` holds an operator's choices: certificate names from the eIM
builder store plus the typed EimConfigurationData members.
``build_add_initial_eim`` turns them into one AddInitialEimRequest, checks the
bytes read back, records the typed values in the store and returns the APDU
sequence of the run, eUICCMemoryReset first. ``run_wizard`` asks for the same
inputs in a terminal, one member per step.
"""

from __future__ import annotations

import binascii
import dataclasses
import datetime
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from SCP11.shared.eim_builder_store import (
    MAX_SOURCE_BYTES,
    EimBuilderStoreError,
    StoredCertificate,
    certificates_from_source,
    describe_certificate,
    import_certificates,
    list_certificates,
    load_configurations,
    load_last_build,
    load_last_configuration,
    load_values,
    name_from_subject,
    normalise_name,
    read_certificate,
    remember_last_configuration,
    remember_values,
    save_configuration,
)
from SCP11.shared.eim_configuration_data import (
    ADD_INITIAL_EIM_RESET_OPTIONS,
    COUNTER_VALUE_GUARANTEED_MAX,
    EIM_ID_TYPE_NAMES,
    EIM_ID_TYPES,
    EIM_SUPPORTED_PROTOCOL_BITS,
    KEY_FORM_CERTIFICATE,
    KEY_FORM_PUBLIC_KEY,
    SCRIPT_LOGICAL_CHANNEL,
    EimConfigurationData,
    KeyData,
    ScriptStep,
    add_initial_eim_problems,
    add_initial_eim_script,
    add_initial_eim_single_apdu,
    encode_add_initial_eim_request,
    encode_euicc_memory_reset_request,
    infer_eim_id_type,
    verify_add_initial_eim_request,
)

EIM_ID_TYPE_AUTO = "auto"
EIM_ID_TYPE_OMIT = "omit"
EIM_ID_TYPE_CHOICES: tuple[str, ...] = (EIM_ID_TYPE_AUTO, *EIM_ID_TYPES, EIM_ID_TYPE_OMIT)
EIM_ID_TYPE_SHORTHAND: dict[str, str] = {
    "oid": "eimIdTypeOid",
    "fqdn": "eimIdTypeFqdn",
    "proprietary": "eimIdTypeProprietary",
    "prop": "eimIdTypeProprietary",
}
# Shorthand the wizard reads for the two key-data alternatives.
KEY_FORM_SHORTHAND: dict[str, str] = {
    "cert": KEY_FORM_CERTIFICATE,
    "certificate": KEY_FORM_CERTIFICATE,
    "key": KEY_FORM_PUBLIC_KEY,
    "publickey": KEY_FORM_PUBLIC_KEY,
    "public-key": KEY_FORM_PUBLIC_KEY,
    "spki": KEY_FORM_PUBLIC_KEY,
}
# Shown with an APDU script, which is replayed outside the console's own channel handling.
SCRIPT_CHANNEL_NOTE = (
    f"The script assumes MANAGE CHANNEL answers channel {SCRIPT_LOGICAL_CHANNEL:02X} (no other logical "
    "channel open); the card assigns the number."
)

# eimPublicKeyData and trustedPublicKeyDataTls alternatives by their ASN.1 names.
EIM_KEY_FORMS: dict[str, str] = {
    "eimCertificate": KEY_FORM_CERTIFICATE,
    "eimPublicKey": KEY_FORM_PUBLIC_KEY,
}
TLS_KEY_FORMS: dict[str, str] = {
    "trustedCertificateTls": KEY_FORM_CERTIFICATE,
    "trustedEimPkTls": KEY_FORM_PUBLIC_KEY,
}
DEFAULT_SUPPORTED_PROTOCOL: tuple[str, ...] = ("eimRetrieveHttps",)

_HEX_SEPARATORS = re.compile(r"[\s:]")


class EimBuilderError(ValueError):
    """An input the operator has to correct before a request can be built."""


@dataclass(frozen=True)
class BuilderInputs:
    """What an operator chooses for one AddInitialEim run."""

    eim_id: str
    eim_certificate: str
    eim_key_form: str = "eimCertificate"
    eim_id_type: str = EIM_ID_TYPE_AUTO
    eim_fqdn: str = ""
    counter_value: int = 0
    association_token: bool = False
    tls_certificate: str = ""
    tls_key_form: str = "trustedCertificateTls"
    eim_supported_protocol: tuple[str, ...] | None = DEFAULT_SUPPORTED_PROTOCOL
    euicc_ci_pk_id: str = ""
    indirect_profile_download: bool = False


@dataclass(frozen=True)
class Finding:
    severity: str
    text: str


@dataclass(frozen=True)
class BuildResult:
    """One built AddInitialEimRequest with everything a surface shows about it."""

    inputs: BuilderInputs
    entry: EimConfigurationData
    request: bytes
    reset_request: bytes
    script: tuple[ScriptStep, ...]
    eim_certificate: StoredCertificate
    tls_certificate: StoredCertificate | None
    findings: tuple[Finding, ...]

    def script_text(self) -> str:
        return "\n".join(step.apdu_hex for step in self.script)

    @property
    def request_apdu(self) -> ScriptStep:
        """The request as one STORE DATA APDU, an extended Lc past 255 bytes."""
        return add_initial_eim_single_apdu(self.request)

    def summary_rows(self) -> list[tuple[int, str, str]]:
        """``(indent, label, value)`` rows describing the request member by member."""
        entry = self.entry
        rows: list[tuple[int, str, str]] = [
            (0, "AddInitialEimRequest", f"{len(self.request)} bytes, 1 EimConfigurationData"),
            (1, "eimId", entry.eim_id or ""),
        ]
        rows.append((1, "eimFqdn", entry.eim_fqdn if entry.eim_fqdn is not None else "(omitted)"))
        if entry.eim_id_type is None:
            rows.append((1, "eimIdType", "(omitted: the eUICC stores eimIdTypeProprietary)"))
        else:
            rows.append((1, "eimIdType", f"{EIM_ID_TYPE_NAMES.get(entry.eim_id_type, '?')} ({entry.eim_id_type})"))
        rows.append((1, "counterValue", str(entry.counter_value)))
        if entry.association_token is None:
            rows.append((1, "associationToken", "(omitted)"))
        else:
            rows.append((1, "associationToken", "-1 (the eUICC assigns one and answers it)"))
        rows.append((1, "eimPublicKeyData", self._key_text(entry.eim_public_key_data, self.eim_certificate)))
        rows.append(
            (1, "trustedPublicKeyDataTls", self._key_text(entry.trusted_public_key_data_tls, self.tls_certificate))
        )
        if entry.eim_supported_protocol is None:
            rows.append((1, "eimSupportedProtocol", "(omitted: the eUICC stores eimProprietary only)"))
        else:
            rows.append((1, "eimSupportedProtocol", ", ".join(entry.eim_supported_protocol) or "(no bit set)"))
        if entry.euicc_ci_pk_id is None:
            rows.append((1, "euiccCiPKId", "(omitted: the first euiccCiPKIdListForSigning entry)"))
        else:
            rows.append((1, "euiccCiPKId", entry.euicc_ci_pk_id.hex().upper()))
        rows.append((1, "indirectProfileDownload", "present" if entry.indirect_profile_download else "(omitted)"))
        rows.append(
            (0, "eUICCMemoryReset", f"{self.reset_request.hex().upper()} ({', '.join(ADD_INITIAL_EIM_RESET_OPTIONS)})")
        )
        return rows

    @staticmethod
    def _key_text(key: KeyData | None, certificate: StoredCertificate | None) -> str:
        if key is None or certificate is None:
            return "(omitted)"
        form = "certificate" if key.form == KEY_FORM_CERTIFICATE else "public key of"
        return f"{form} {certificate.name}: {certificate.summary()}"


def parse_hex(text: str, label: str) -> bytes:
    compact = _HEX_SEPARATORS.sub("", str(text or ""))
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    try:
        return binascii.unhexlify(compact)
    except (binascii.Error, ValueError) as error:
        raise EimBuilderError(f"{label} is not valid hex: {error}") from error


def parse_protocol_names(text: str) -> tuple[str, ...]:
    """Read eimSupportedProtocol bits given by name or by 1-based number, comma or space separated."""
    names: list[str] = []
    for token in re.split(r"[,\s]+", str(text or "").strip()):
        if not token:
            continue
        if token.isdigit():
            index = int(token) - 1
            if index < 0 or index >= len(EIM_SUPPORTED_PROTOCOL_BITS):
                raise EimBuilderError(f"Protocol number {token} is outside 1..{len(EIM_SUPPORTED_PROTOCOL_BITS)}.")
            name = EIM_SUPPORTED_PROTOCOL_BITS[index]
        else:
            matches = [bit for bit in EIM_SUPPORTED_PROTOCOL_BITS if bit.casefold() == token.casefold()]
            if not matches:
                raise EimBuilderError(
                    f"Unknown eimSupportedProtocol bit {token!r}; expected one of: "
                    + ", ".join(EIM_SUPPORTED_PROTOCOL_BITS)
                    + "."
                )
            name = matches[0]
        if name not in names:
            names.append(name)
    return tuple(names)


def canonical_eim_id_type(choice: str) -> str:
    """Return the eimIdType choice a name or shorthand stands for (``oid`` -> ``eimIdTypeOid``)."""
    text = str(choice or EIM_ID_TYPE_AUTO).strip()
    folded = text.casefold()
    for name in EIM_ID_TYPE_CHOICES:
        if folded == name.casefold():
            return name
    canonical = EIM_ID_TYPE_SHORTHAND.get(folded)
    if canonical is None:
        raise EimBuilderError(
            f"eimIdType {text!r} is not one of: {', '.join(EIM_ID_TYPE_CHOICES)} "
            f"(or {', '.join(sorted(EIM_ID_TYPE_SHORTHAND))})."
        )
    return canonical


def _resolve_eim_id_type(choice: str, eim_id: str) -> int | None:
    text = canonical_eim_id_type(choice)
    if text == EIM_ID_TYPE_OMIT:
        return None
    if text == EIM_ID_TYPE_AUTO:
        return infer_eim_id_type(eim_id)
    code = EIM_ID_TYPES[text]
    if code == EIM_ID_TYPES["eimIdTypeOid"] and infer_eim_id_type(eim_id) != code:
        raise EimBuilderError(
            f"eimIdType eimIdTypeOid needs the eimId as a dotted OID, not {eim_id!r} "
            "(SGP.32 v1.3 §4.3: an eimId of that type SHALL be encoded using the OID)."
        )
    if code == EIM_ID_TYPES["eimIdTypeFqdn"] and infer_eim_id_type(eim_id) != code:
        raise EimBuilderError(
            f"eimIdType eimIdTypeFqdn needs the eimId as a host name, not {eim_id!r} (SGP.32 v1.3 §4.3: an eimId of "
            "that type SHALL be encoded as a FQDN). The eUICC's IPA contacts the eimId as the host and no eimFqdn "
            "goes with that type; for an OID eimId with a separate eimFqdn, choose eimIdTypeOid."
        )
    return code


def _key_form(choice: str, forms: dict[str, str], member: str) -> str:
    text = str(choice or "").strip()
    if text in forms:
        return forms[text]
    raise EimBuilderError(f"{member} alternative {text!r} is not one of: {', '.join(forms)}.")


def _load_certificate(name: str, member: str, directory: Path | None) -> StoredCertificate:
    try:
        return read_certificate(name, directory)
    except EimBuilderStoreError as error:
        raise EimBuilderError(f"{member}: {error}") from error


def _findings(
    entry: EimConfigurationData,
    eim_certificate: StoredCertificate,
    tls_certificate: StoredCertificate | None,
    today: datetime.datetime,
) -> list[Finding]:
    # The eimId is free text: nothing here compares it with a certificate.
    findings: list[Finding] = []
    if entry.counter_value is not None and entry.counter_value > COUNTER_VALUE_GUARANTEED_MAX:
        findings.append(
            Finding(
                "warning",
                f"counterValue {entry.counter_value} is above {COUNTER_VALUE_GUARANTEED_MAX}, the largest value every "
                "eUICC handles (SGP.32 v1.3 §2.11.1.1.1); a smaller limit answers counterValueOutOfRange.",
            )
        )
    for certificate, member in ((eim_certificate, "eimPublicKeyData"), (tls_certificate, "trustedPublicKeyDataTls")):
        if certificate is None:
            continue
        try:
            expiry = datetime.datetime.strptime(certificate.not_after, "%Y-%m-%d %H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc
            )
        except ValueError:
            continue
        if expiry < today:
            findings.append(Finding("warning", f"{member}: {certificate.name} expired on {certificate.not_after}."))
    if tls_certificate is not None and not tls_certificate.ski_hex:
        findings.append(
            Finding(
                "warning",
                f"trustedPublicKeyDataTls: {tls_certificate.name} has no SubjectKeyIdentifier extension, "
                "which SGP.32 v1.3 §2.11.1.1.1 requires of trustedCertificateTls.",
            )
        )
    retrieve = {"eimRetrieveHttps", "eimRetrieveCoaps"} & set(entry.eim_supported_protocol or ())
    if tls_certificate is None and retrieve:
        findings.append(
            Finding(
                "note",
                "No trustedPublicKeyDataTls: an IPAe retrieving over "
                + " or ".join(sorted(retrieve))
                + " needs trustedCertificateTls (SGP.32 v1.3 §2.11.1.1.1 NOTE).",
            )
        )
    if entry.indirect_profile_download:
        findings.append(
            Finding("note", "indirectProfileDownload [9] is an SGP.32 v1.3 member; v1.2 does not define it.")
        )
    return findings


def build_add_initial_eim(
    inputs: BuilderInputs,
    *,
    directory: Path | None = None,
    remember: bool = True,
    now: datetime.datetime | None = None,
) -> BuildResult:
    """Build, verify and describe one AddInitialEim run; raises ``EimBuilderError`` on a bad input."""
    eim_id = str(inputs.eim_id or "").strip()
    if not eim_id:
        raise EimBuilderError("eimId is required.")
    eim_name = str(inputs.eim_certificate or "").strip()
    if not eim_name:
        raise EimBuilderError("Choose the eIM certificate (eimPublicKeyData) from the store.")
    eim_certificate = _load_certificate(eim_name, "eimPublicKeyData", directory)
    eim_form = _key_form(inputs.eim_key_form, EIM_KEY_FORMS, "eimPublicKeyData")
    tls_certificate: StoredCertificate | None = None
    tls_key: KeyData | None = None
    tls_name = str(inputs.tls_certificate or "").strip()
    if tls_name:
        tls_certificate = _load_certificate(tls_name, "trustedPublicKeyDataTls", directory)
        tls_form = _key_form(inputs.tls_key_form, TLS_KEY_FORMS, "trustedPublicKeyDataTls")
        tls_der = tls_certificate.der if tls_form == KEY_FORM_CERTIFICATE else tls_certificate.spki_der
        tls_key = KeyData(tls_form, tls_der)
    if isinstance(inputs.counter_value, bool) or not isinstance(inputs.counter_value, int):
        raise EimBuilderError("counterValue must be a whole number.")
    ci_text = str(inputs.euicc_ci_pk_id or "").strip()
    euicc_ci_pk_id = parse_hex(ci_text, "euiccCiPKId") if ci_text else None
    if euicc_ci_pk_id is not None and len(euicc_ci_pk_id) == 0:
        euicc_ci_pk_id = None
    protocol = None
    if inputs.eim_supported_protocol is not None:
        protocol = tuple(inputs.eim_supported_protocol)
        if not protocol:
            protocol = None
    fqdn = str(inputs.eim_fqdn or "").strip()
    typed_eim_id = eim_id
    dropped_fqdn = ""
    replaced_eim_id = ""
    fqdn_code = EIM_ID_TYPES["eimIdTypeFqdn"]
    if canonical_eim_id_type(inputs.eim_id_type) == "eimIdTypeFqdn" and len(fqdn) > 0:
        # SGP.32 v1.3 §4.3 / §2.11.1.1.1: with eimIdTypeFqdn the eimId is the FQDN and no eimFqdn goes with
        # it, so the host typed as eimFqdn is what the entry carries, as its eimId.
        if infer_eim_id_type(fqdn) != fqdn_code:
            raise EimBuilderError(f"eimIdType eimIdTypeFqdn needs a host name; eimFqdn {fqdn!r} does not read as one.")
        if infer_eim_id_type(eim_id) != fqdn_code:
            replaced_eim_id, eim_id = eim_id, fqdn
        elif eim_id.rstrip(".").lower() != fqdn.rstrip(".").lower():
            raise EimBuilderError(
                f"eimIdType eimIdTypeFqdn carries one host name, as the eimId; eimId {eim_id!r} and eimFqdn {fqdn!r} "
                "name two. Leave eimFqdn empty or make them the same."
            )
        dropped_fqdn, fqdn = fqdn, ""
    id_type = _resolve_eim_id_type(inputs.eim_id_type, eim_id)
    if id_type == fqdn_code and len(fqdn) > 0:
        # eimIdType auto with a host name as the eimId: the same rule.
        if eim_id.rstrip(".").lower() != fqdn.rstrip(".").lower():
            raise EimBuilderError(
                f"The eimId {eim_id!r} reads as a host name (eimIdTypeFqdn), which carries no separate eimFqdn; "
                f"eimFqdn {fqdn!r} names another host. Leave eimFqdn empty or make them the same."
            )
        dropped_fqdn, fqdn = fqdn, ""
    eim_der = eim_certificate.der if eim_form == KEY_FORM_CERTIFICATE else eim_certificate.spki_der
    entry = EimConfigurationData(
        eim_id=eim_id,
        eim_fqdn=fqdn or None,
        eim_id_type=id_type,
        counter_value=inputs.counter_value,
        association_token=-1 if inputs.association_token else None,
        eim_public_key_data=KeyData(eim_form, eim_der),
        trusted_public_key_data_tls=tls_key,
        eim_supported_protocol=protocol,
        euicc_ci_pk_id=euicc_ci_pk_id,
        indirect_profile_download=bool(inputs.indirect_profile_download),
    )
    problems = add_initial_eim_problems([entry])
    if problems:
        raise EimBuilderError(" ".join(problems))
    try:
        request = encode_add_initial_eim_request([entry])
        verify_add_initial_eim_request(request, [entry])
    except (TypeError, ValueError) as error:
        raise EimBuilderError(f"The request did not build: {error}") from error
    findings = _findings(
        entry,
        eim_certificate,
        tls_certificate,
        now or datetime.datetime.now(datetime.timezone.utc),
    )
    if len(replaced_eim_id) > 0:
        findings.append(
            Finding(
                "warning",
                f"eimIdType is eimIdTypeFqdn: the entry carries the host {eim_id!r} as its eimId (SGP.32 v1.3 §4.3) "
                f"and no eimFqdn (§2.11.1.1.1). The typed eimId {replaced_eim_id!r} is not sent: the eUICC knows this "
                f"eIM as {eim_id!r}, and an eUICC Package naming another eimId is refused. To keep the OID as the "
                "eimId with the host beside it, choose eimIdTypeOid.",
            )
        )
    elif len(dropped_fqdn) > 0:
        findings.append(
            Finding(
                "note",
                f"eimIdType is eimIdTypeFqdn: the host {eim_id!r} goes as the eimId, with no separate eimFqdn "
                "(SGP.32 v1.3 §2.11.1.1.1).",
            )
        )
    if remember:
        try:
            remember_values(
                {
                    "eim_id": typed_eim_id,
                    "eim_fqdn": fqdn or dropped_fqdn,
                    "euicc_ci_pk_id": euicc_ci_pk_id.hex().upper() if euicc_ci_pk_id else "",
                    "eim_certificate": eim_certificate.name,
                    "tls_certificate": tls_certificate.name if tls_certificate else "",
                },
                directory,
            )
        except (EimBuilderStoreError, OSError) as error:
            findings.append(Finding("warning", f"The typed values were not saved: {error}"))
        try:
            # The whole form, settings included, for the forms and the wizard to start from.
            remember_last_configuration(configuration_from_inputs(inputs), directory)
        except (EimBuilderStoreError, OSError) as error:
            findings.append(Finding("warning", f"The form was not saved as the last build: {error}"))
    return BuildResult(
        inputs=inputs,
        entry=entry,
        request=request,
        reset_request=encode_euicc_memory_reset_request(ADD_INITIAL_EIM_RESET_OPTIONS),
        script=add_initial_eim_script(request),
        eim_certificate=eim_certificate,
        tls_certificate=tls_certificate,
        findings=tuple(findings),
    )


# ----------------------------------------------------------------------
# Terminal wizard
# ----------------------------------------------------------------------

Ask = Callable[[str], str]
Emit = Callable[[str], None]

_CANCEL_WORDS = frozenset({"CANCEL", "/CANCEL", "ABORT", "/ABORT"})
_SKIP_WORD = "SKIP"


class WizardCancelled(Exception):
    """The operator left the wizard; nothing was built or sent."""


def _ask(ask: Ask, prompt: str) -> str:
    try:
        answer = ask(prompt)
    except (EOFError, KeyboardInterrupt) as error:
        raise WizardCancelled() from error
    text = str(answer or "").strip()
    if text.upper() in _CANCEL_WORDS:
        raise WizardCancelled()
    return text


def _ask_until(ask: Ask, emit: Emit, prompt: str, parse: Callable[[str], object]) -> object:
    while True:
        answer = _ask(ask, prompt)
        try:
            return parse(answer)
        except (EimBuilderError, EimBuilderStoreError) as error:
            emit(f"    [!] {error}")


def _numbered(emit: Emit, items: list[str]) -> None:
    for index, item in enumerate(items, start=1):
        emit(f"      [{index}] {item}")


def _pick_saved(answer: str, saved: list[str]) -> str:
    if answer.isdigit() and 1 <= int(answer) <= len(saved):
        return saved[int(answer) - 1]
    return answer


def _choose_certificate(
    ask: Ask,
    emit: Emit,
    member: str,
    default: str,
    *,
    optional: bool,
    directory: Path | None,
) -> str:
    """Pick a stored certificate by number or name, or import one from a file path."""
    entries, problems = list_certificates(directory)
    for problem in problems:
        emit(f"    [!] {problem}")
    names = [entry.name for entry in entries]
    emit(f"  {member}: a stored certificate (number or name), or the path of a PEM, DER, base64 or hex file.")
    _numbered(emit, [f"{entry.name}: {entry.summary()}" for entry in entries])
    if default and default not in names:
        default = ""
    hint = []
    if default:
        hint.append(f"Enter = {default}")
    if optional:
        hint.append("SKIP = omit")
    prompt = f"  > {member}" + (f" [{', '.join(hint)}]" if hint else "") + ": "

    def parse(answer: str) -> str:
        if not answer:
            if default:
                return default
            if optional:
                return ""
            raise EimBuilderError(f"{member} is mandatory; give a number, a stored name or a file path.")
        if optional and answer.upper() == _SKIP_WORD:
            return ""
        if answer.isdigit() and 1 <= int(answer) <= len(names):
            return names[int(answer) - 1]
        if answer in names:
            return answer
        path = Path(answer).expanduser()
        if path.is_file():
            return _import_from_path(ask, emit, path, entries, directory)
        raise EimBuilderError(f"{answer!r} is neither a listed number, a stored name nor a readable file.")

    return str(_ask_until(ask, emit, prompt, parse))


def _import_from_path(
    ask: Ask,
    emit: Emit,
    path: Path,
    entries: list[StoredCertificate],
    directory: Path | None,
) -> str:
    """Store the certificates of a file under a name the operator confirms; reuse an identical stored one."""
    from yggdrasim_common.secure_files import read_bounded_regular_file

    try:
        raw = read_bounded_regular_file(path, MAX_SOURCE_BYTES)
    except (OSError, ValueError) as error:
        raise EimBuilderError(f"{path} could not be read: {error}") from error
    certificates, _private_keys = certificates_from_source(raw)
    first = describe_certificate(certificates[0])
    for entry in entries:
        if entry.sha256_hex == first.sha256_hex:
            emit(f"    [*] Already stored as {entry.name}.")
            return entry.name
    taken = {entry.name for entry in entries}
    stem = name_from_subject(first.subject_cn)
    suggested = stem
    suffix = 2
    while suggested in taken:
        suggested = f"{stem[:60]}-{suffix}"
        suffix += 1

    def parse_name(answer: str) -> str:
        name = normalise_name(answer or suggested)
        if name in taken:
            raise EimBuilderError(f"{name} is already stored; choose another name.")
        return name

    name = str(_ask_until(ask, emit, f"  > Store {first.subject_cn or 'it'} as [Enter = {suggested}]: ", parse_name))
    report = import_certificates(raw, name=name, directory=directory)
    for stored in report.stored:
        emit(f"    [+] Stored {stored.name}: {stored.summary()}")
    if report.private_keys_dropped:
        emit(f"    [*] {report.private_keys_dropped} private key block(s) in the file were not stored.")
    return report.stored[0].name


def _choose_value(ask: Ask, emit: Emit, label: str, saved: list[str], default: str, *, optional: bool) -> str:
    if saved:
        emit(f"  Saved {label} values:")
        _numbered(emit, saved)
    hint = []
    if default:
        hint.append(f"Enter = {default}")
    if optional:
        hint.append("SKIP = omit")
    prompt = f"  > {label}" + (f" [{', '.join(hint)}]" if hint else "") + ": "

    def parse(answer: str) -> str:
        if not answer:
            if default:
                return default
            if optional:
                return ""
            raise EimBuilderError(f"{label} is mandatory.")
        if optional and answer.upper() == _SKIP_WORD:
            return ""
        return _pick_saved(answer, saved)

    return str(_ask_until(ask, emit, prompt, parse))


def _choose_option(
    ask: Ask,
    emit: Emit,
    label: str,
    options: list[str],
    default: str,
    *,
    shorthand: dict[str, str] | None = None,
    check: Callable[[str], None] | None = None,
) -> str:
    """Pick one option by number, by name (any case) or by shorthand; ``check`` may refuse it."""
    _numbered(emit, options)
    prompt = f"  > {label} [Enter = {default}]: "
    words = {key.casefold(): value for key, value in (shorthand or {}).items()}

    def parse(answer: str) -> str:
        chosen = ""
        if not answer:
            chosen = default
        elif answer.isdigit() and 1 <= int(answer) <= len(options):
            chosen = options[int(answer) - 1]
        else:
            for option in options:
                if option.casefold() == answer.casefold():
                    chosen = option
            chosen = chosen or words.get(answer.casefold(), "")
        if not chosen:
            extra = f" (or {', '.join(sorted(words))})" if words else ""
            raise EimBuilderError(f"Choose a number or one of: {', '.join(options)}{extra}.")
        if check is not None:
            check(chosen)
        return chosen

    return str(_ask_until(ask, emit, prompt, parse))


def _form_shorthand(forms: dict[str, str]) -> dict[str, str]:
    """Map the key-data shorthand (``cert``, ``key``) onto one member's alternative names."""
    return {word: name for word, form in KEY_FORM_SHORTHAND.items() for name, value in forms.items() if value == form}


def _choose_bool(ask: Ask, emit: Emit, label: str, default: bool) -> bool:
    prompt = f"  > {label} [y/n, Enter = {'y' if default else 'n'}]: "

    def parse(answer: str) -> bool:
        if not answer:
            return default
        if answer.upper() in ("Y", "YES"):
            return True
        if answer.upper() in ("N", "NO"):
            return False
        raise EimBuilderError("Answer y or n.")

    return bool(_ask_until(ask, emit, prompt, parse))


def _choose_counter(ask: Ask, emit: Emit, default: int = 0) -> int:
    def parse(answer: str) -> int:
        if not answer:
            return default
        if answer.isdigit() is False:
            raise EimBuilderError("counterValue is a whole number, 0 or more.")
        return int(answer)

    return int(_ask_until(ask, emit, f"  > counterValue [Enter = {default}]: ", parse))


def _choose_protocol(
    ask: Ask,
    emit: Emit,
    default: tuple[str, ...] | None = DEFAULT_SUPPORTED_PROTOCOL,
) -> tuple[str, ...] | None:
    _numbered(emit, list(EIM_SUPPORTED_PROTOCOL_BITS))
    shown = ", ".join(default) if default else "omit"
    prompt = f"  > eimSupportedProtocol, numbers or names [Enter = {shown}, SKIP = omit]: "

    def parse(answer: str) -> tuple[str, ...] | None:
        if not answer:
            return default
        if answer.upper() == _SKIP_WORD:
            return None
        names = parse_protocol_names(answer)
        if not names:
            raise EimBuilderError("Name at least one bit, or SKIP to omit the member.")
        return names

    result = _ask_until(ask, emit, prompt, parse)
    return None if result is None else tuple(result)


def _choose_ci_pk_id(ask: Ask, emit: Emit, saved: list[str], default: str) -> str:
    if saved:
        emit("  Saved euiccCiPKId values:")
        _numbered(emit, saved)
    hint = [f"Enter = {default}"] if default else []
    hint.append("SKIP = omit")
    prompt = f"  > euiccCiPKId (hex) [{', '.join(hint)}]: "

    def parse(answer: str) -> str:
        if not answer:
            return default
        if answer.upper() == _SKIP_WORD:
            return ""
        value = _pick_saved(answer, saved)
        if not parse_hex(value, "euiccCiPKId"):
            raise EimBuilderError("euiccCiPKId is empty.")
        return parse_hex(value, "euiccCiPKId").hex().upper()

    return str(_ask_until(ask, emit, prompt, parse))


def run_wizard(
    ask: Ask,
    emit: Emit,
    *,
    directory: Path | None = None,
    base: BuilderInputs | None = None,
) -> BuilderInputs | None:
    """Ask for each EimConfigurationData member in turn; ``None`` when the operator cancels.

    Enter keeps the offered default: ``base`` (a saved configuration) when
    given, else the last build's value. The eimId is free text, never read
    from a certificate. Options take a number, a name or shorthand (``oid``,
    ``cert``); SKIP leaves an optional member out and CANCEL leaves the wizard
    at any prompt.
    """
    try:
        saved = load_values(directory)
        last_build = load_last_build(directory)
    except EimBuilderStoreError as error:
        emit(f"  [!] Saved values unavailable: {error}")
        saved = {}
        last_build = {}

    def last(field: str) -> str:
        if field in last_build:
            return last_build[field]
        values = saved.get(field) or []
        return values[0] if values else ""

    if base is None:
        try:
            remembered = load_last_configuration(directory)
            base = inputs_from_configuration(remembered) if remembered else None
        except (EimBuilderStoreError, EimBuilderError) as error:
            emit(f"  [!] The last build's form is unavailable: {error}")
            base = None
    if base is None:
        base = BuilderInputs(
            eim_id=last("eim_id"),
            eim_certificate=last("eim_certificate"),
            eim_fqdn=last("eim_fqdn"),
            tls_certificate=last("tls_certificate"),
            euicc_ci_pk_id=last("euicc_ci_pk_id"),
        )

    emit("  Type CANCEL at any prompt to leave without building or sending anything.")
    try:
        emit("")
        emit("  Step 1/12 eimPublicKeyData")
        eim_certificate = _choose_certificate(
            ask, emit, "eIM certificate", base.eim_certificate, optional=False, directory=directory
        )
        emit("  Step 2/12 eimPublicKeyData alternative")
        eim_key_form = _choose_option(
            ask,
            emit,
            "eimPublicKeyData",
            list(EIM_KEY_FORMS),
            base.eim_key_form if base.eim_key_form in EIM_KEY_FORMS else "eimCertificate",
            shorthand=_form_shorthand(EIM_KEY_FORMS),
        )
        emit("  Step 3/12 eimId (free text, at most 128 bytes)")
        eim_id = _choose_value(ask, emit, "eimId", saved.get("eim_id") or [], base.eim_id, optional=False)
        emit(f"  Step 4/12 eimIdType (auto reads {EIM_ID_TYPE_NAMES[infer_eim_id_type(eim_id)]} from the eimId)")

        def check_type(choice: str) -> None:
            _resolve_eim_id_type(choice, eim_id)

        eim_id_type = _choose_option(
            ask,
            emit,
            "eimIdType",
            list(EIM_ID_TYPE_CHOICES),
            base.eim_id_type if base.eim_id_type in EIM_ID_TYPE_CHOICES else EIM_ID_TYPE_AUTO,
            shorthand=EIM_ID_TYPE_SHORTHAND,
            check=check_type,
        )
        emit("  Step 5/12 eimFqdn")
        eim_fqdn = _choose_value(ask, emit, "eimFqdn", saved.get("eim_fqdn") or [], base.eim_fqdn, optional=True)
        emit("  Step 6/12 counterValue")
        counter_value = _choose_counter(ask, emit, base.counter_value)
        emit("  Step 7/12 associationToken")
        association_token = _choose_bool(ask, emit, "Request an associationToken (-1)", base.association_token)
        emit("  Step 8/12 trustedPublicKeyDataTls")
        tls_certificate = _choose_certificate(
            ask, emit, "TLS certificate", base.tls_certificate, optional=True, directory=directory
        )
        tls_key_form = "trustedCertificateTls"
        emit("  Step 9/12 trustedPublicKeyDataTls alternative")
        if tls_certificate:
            tls_key_form = _choose_option(
                ask,
                emit,
                "trustedPublicKeyDataTls",
                list(TLS_KEY_FORMS),
                base.tls_key_form if base.tls_key_form in TLS_KEY_FORMS else "trustedCertificateTls",
                shorthand=_form_shorthand(TLS_KEY_FORMS),
            )
        else:
            emit("    (skipped: no TLS certificate)")
        emit("  Step 10/12 eimSupportedProtocol")
        protocol = _choose_protocol(ask, emit, base.eim_supported_protocol)
        emit("  Step 11/12 euiccCiPKId")
        euicc_ci_pk_id = _choose_ci_pk_id(ask, emit, saved.get("euicc_ci_pk_id") or [], base.euicc_ci_pk_id)
        emit("  Step 12/12 indirectProfileDownload")
        indirect = _choose_bool(ask, emit, "indirectProfileDownload", base.indirect_profile_download)
    except WizardCancelled:
        emit("  [-] Wizard cancelled; nothing was built or sent.")
        return None
    return BuilderInputs(
        eim_id=eim_id,
        eim_certificate=eim_certificate,
        eim_key_form=eim_key_form,
        eim_id_type=eim_id_type,
        eim_fqdn=eim_fqdn,
        counter_value=counter_value,
        association_token=association_token,
        tls_certificate=tls_certificate,
        tls_key_form=tls_key_form,
        eim_supported_protocol=protocol,
        euicc_ci_pk_id=euicc_ci_pk_id,
        indirect_profile_download=indirect,
    )


# ----------------------------------------------------------------------
# Saved configurations
# ----------------------------------------------------------------------

CONFIGURATION_KEYS: tuple[str, ...] = tuple(member.name for member in dataclasses.fields(BuilderInputs))


def configuration_from_inputs(inputs: BuilderInputs) -> dict[str, Any]:
    """Return the store form of one set of builder inputs."""
    values = dataclasses.asdict(inputs)
    protocol = values.get("eim_supported_protocol")
    values["eim_supported_protocol"] = None if protocol is None else list(protocol)
    return values


def inputs_from_configuration(values: Mapping[str, Any]) -> BuilderInputs:
    """Rebuild builder inputs from a stored configuration; a key it lacks keeps its default."""
    changes: dict[str, Any] = {}
    for key in CONFIGURATION_KEYS:
        if key not in values:
            continue
        value = values[key]
        if key == "counter_value":
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EimBuilderError("The configuration's counterValue is not a whole number.")
        elif key in ("association_token", "indirect_profile_download"):
            if not isinstance(value, bool):
                raise EimBuilderError(f"The configuration's {key} is not true or false.")
        elif key == "eim_supported_protocol":
            if value is not None:
                if not isinstance(value, (list, tuple)):
                    raise EimBuilderError("The configuration's eimSupportedProtocol is not a list of bits.")
                value = parse_protocol_names(" ".join(str(item) for item in value))
        elif not isinstance(value, str):
            raise EimBuilderError(f"The configuration's {key} is not text.")
        changes[key] = value
    if "eim_id_type" in changes:
        changes["eim_id_type"] = canonical_eim_id_type(changes["eim_id_type"])
    return dataclasses.replace(BuilderInputs(eim_id="", eim_certificate=""), **changes)


def configuration_summary(values: Mapping[str, Any]) -> str:
    parts = [str(values.get("eim_id") or "(no eimId)")]
    if values.get("eim_fqdn"):
        parts.append(str(values["eim_fqdn"]))
    parts.append(f"eIM certificate {values.get('eim_certificate') or '?'}")
    parts.append(f"TLS {values.get('tls_certificate') or 'none'}")
    return ", ".join(parts)


@dataclass(frozen=True)
class WizardOutcome:
    """Wizard inputs and the configuration they started from (empty for the last build)."""

    inputs: BuilderInputs
    configuration: str = ""


def run_configured_wizard(ask: Ask, emit: Emit, *, directory: Path | None = None) -> WizardOutcome | None:
    """Offer the saved configurations as a starting point, then run the wizard from it."""
    try:
        configurations = load_configurations(directory)
    except EimBuilderStoreError as error:
        emit(f"  [!] Saved configurations unavailable: {error}")
        configurations = {}
    chosen = ""
    base: BuilderInputs | None = None
    if configurations:
        names = sorted(configurations)
        emit("  Saved configurations:")
        _numbered(emit, [f"{name}: {configuration_summary(configurations[name])}" for name in names])

        def parse(answer: str) -> tuple[str, BuilderInputs | None]:
            if not answer:
                return "", None
            name = names[int(answer) - 1] if answer.isdigit() and 1 <= int(answer) <= len(names) else answer
            if name not in configurations:
                raise EimBuilderError(f"No configuration named {name!r}; give a number or a listed name.")
            return name, inputs_from_configuration(configurations[name])

        prompt = "  > Start from a configuration [number or name, Enter = the last build]: "
        try:
            chosen, base = _ask_until(ask, emit, prompt, parse)  # type: ignore[misc]
        except WizardCancelled:
            emit("  [-] Wizard cancelled; nothing was built or sent.")
            return None
        if chosen:
            emit(f"  Starting from configuration {chosen}; Enter keeps its values.")
    inputs = run_wizard(ask, emit, directory=directory, base=base)
    if inputs is None:
        return None
    return WizardOutcome(inputs=inputs, configuration=chosen)


def offer_save_configuration(
    ask: Ask,
    emit: Emit,
    inputs: BuilderInputs,
    loaded: str = "",
    *,
    directory: Path | None = None,
) -> str:
    """Ask whether to store ``inputs`` as a configuration; returns the name saved, or an empty string."""
    hint = "a name to save, Enter = skip" + (f"; {loaded} updates it" if loaded else "")

    def parse(answer: str) -> str:
        if not answer:
            return ""
        return save_configuration(answer, configuration_from_inputs(inputs), directory)

    try:
        name = str(_ask_until(ask, emit, f"  > Save these values as a configuration [{hint}]: ", parse))
    except WizardCancelled:
        return ""
    if name:
        emit(f"    [+] Saved configuration {name}.")
    return name
