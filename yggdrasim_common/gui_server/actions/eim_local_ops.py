# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Command Center actions for the Local eIM operation queue.

Each action runs the eIM-local shell verb of the same name
(``SCP11.eim_local.engine_shell``) with the form's values, so the GUI and the
shell queue, edit and deliver the same way and print the same lines. Card
actions open the chosen reader for the one call; everything else works on the
engine store alone. The new operation form takes any operation type; the
queue, the eUICC records and the background service each get their own tab.
"""

from __future__ import annotations

import dataclasses
import shlex
from typing import Any, Callable

from .registry import ActionContext, ActionField, ActionSpec, get_registry

SUBSYSTEM = "Local eIM"

OPERATION_CHOICES = [
    "LIST-PROFILES", "ENABLE", "DISABLE", "DELETE", "DOWNLOAD", "FALLBACK", "UNSET-FALLBACK",
    "IMMEDIATE-ENABLE", "DEFAULT-SMDP", "GET-RAT", "IPA-DATA", "ADD-EIM", "UPDATE-EIM", "DELETE-EIM",
    "LIST-EIM", "REFRESH", "RAW-PSMO", "RAW-ECO", "ROLLBACK", "EXECUTE-FALLBACK", "RETURN-FALLBACK",
]
FAULT_CHOICES = ["", "stale-counter", "wrong-eid", "bad-signature", "wrong-token", "unknown-eim", "counter-overflow"]


class _Shell:
    """The two attributes the verbs read from a shell: a session and its config."""

    def __init__(self, session: Any) -> None:
        self.session = session


def _offline_session() -> Any:
    """A session for a call that drives no card, and that cannot come to drive one.

    The route claimed no reader for such a call, so nothing keeps it apart
    from whoever holds the reader. ``no_reader`` makes the verbs refuse to
    open a channel instead of trusting that they never get there: a verb
    reads the card whenever its EID argument does not read as an EID.
    """
    from SCP11.eim_local.config import EimLocalConfig
    from SCP11.eim_local.session import EimLocalSession

    session = EimLocalSession(cfg=EimLocalConfig(), apdu_channel=None)
    session.no_reader = True
    return session


def _card_session(reader: str) -> tuple[Any, Any]:
    from SCP11.eim_local.config import EimLocalConfig
    from SCP11.eim_local.session import EimLocalSession
    from SCP11.live.transport import PcscApduChannel, RemoteApduChannel
    from yggdrasim_common.remote_readers import REMOTE_READER_INDEX

    from ..live_trace import configure_channel_trace
    from .scp11_local import _resolve_reader_index

    index = _resolve_reader_index(reader)
    if index == REMOTE_READER_INDEX:
        channel = RemoteApduChannel(str(reader or ""), quiet_apdu_logging=True)
    else:
        channel = PcscApduChannel(reader_index=index, quiet_apdu_logging=True)
    session = EimLocalSession(cfg=EimLocalConfig(READER_INDEX=index), apdu_channel=channel)
    configure_channel_trace(channel)
    return session, channel


def _run(verb: str, argument: str, *, reader: str | None = None) -> dict[str, Any]:
    """Run one verb and return its printed lines; a refusal raises, as an action error.

    A verb that took Notifications from a card sends them on only after the
    card channel is closed here: a receiver that answers slowly must not keep
    the card powered and selected.
    """
    from SCP11.eim_local.engine_shell import EngineVerbs

    from .scp11_local import _close_channel

    lines: list[str] = []
    channel = None
    if reader is None:
        session = _offline_session()
    else:
        session, channel = _card_session(reader)
    try:
        verbs = EngineVerbs(_Shell(session), emit=lines.append)
        verbs.defer_notification_pass = channel is not None
        handler: Callable[[str], None] = getattr(verbs, f"cmd_{verb}")
        handler(argument)
    finally:
        _close_channel(channel)
    if verbs.defer_notification_pass and verb == "deliver":
        verbs.forward_due_notifications()
    return {"lines": lines or ["(no output)"]}


def _quote(value: Any) -> str:
    return shlex.quote(str(value))


def _pairs(text: Any) -> list[str]:
    """key=value lines (or space separated) from a text field, quoted for the verb parser."""
    tokens: list[str] = []
    for line in str(text or "").replace(";", "\n").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for token in shlex.split(stripped):
            tokens.append(_quote(token))
    return tokens


def _flag(value: Any) -> bool:
    """A bool field's value as the form sends it: a bool, or on/off text."""
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _queue_reads_card(inputs: dict[str, Any]) -> bool:
    """Queue reads the card for its EID only when the form names no eUICC."""
    return not _text(inputs.get("eid")) and not _text(inputs.get("eid_file"))


def _import_reads_card(inputs: dict[str, Any]) -> bool:
    return not _text(inputs.get("eid"))


# ----------------------------------------------------------------------
# Dispatchers
# ----------------------------------------------------------------------


def _dispatch_queue(ctx: ActionContext, *, operation: Any = None, eid: Any = None, value: Any = None,
                    params: Any = None, at: Any = None, retries: Any = None, fault: Any = None,
                    first: Any = None, plan: Any = None, raw: Any = None, eid_file: Any = None,
                    reader: Any = None) -> dict[str, Any]:
    parts = [_quote(_text(operation) or "LIST-PROFILES")]
    if _text(eid):
        parts.append(_quote(_text(eid)))
    if _text(value):
        parts.append(_quote(_text(value)))
    parts.extend(_pairs(params))
    for flag, field_value in (("--at", at), ("--fault", fault), ("--raw", raw), ("--eid-file", eid_file)):
        if _text(field_value):
            parts.extend([flag, _quote(_text(field_value))])
    if retries is not None and str(retries).strip() != "":
        parts.extend(["--retries", _quote(int(retries))])
    if first:
        parts.append("--first")
    if plan:
        parts.append("--plan")
    needs_card = _queue_reads_card({"eid": eid, "eid_file": eid_file})
    return _run("queue", " ".join(parts), reader=_text(reader) if needs_card else None)


def _dispatch_list(ctx: ActionContext, *, scope: Any = None, eid: Any = None, type: Any = None,  # noqa: A002 - the form field name
                   limit: Any = None) -> dict[str, Any]:
    parts = [_quote(_text(scope) or "pending")]
    if _text(eid):
        parts.append(_quote(f"eid={_text(eid)}"))
    if _text(type):
        parts.append(_quote(f"type={_text(type)}"))
    if limit is not None and str(limit).strip() != "":
        parts.append(_quote(f"limit={int(limit)}"))
    return _run("ops", " ".join(parts))


def _dispatch_show(ctx: ActionContext, *, operation_id: Any = None) -> dict[str, Any]:
    return _run("op", _quote(int(operation_id)))


def _dispatch_edit(ctx: ActionContext, *, operation_id: Any = None, changes: Any = None) -> dict[str, Any]:
    return _run("edit", " ".join([_quote(int(operation_id)), *_pairs(changes)]))


def _dispatch_move(ctx: ActionContext, *, operation_id: Any = None, where: Any = None,
                   other_id: Any = None) -> dict[str, Any]:
    parts = [_quote(int(operation_id)), _quote(_text(where) or "first")]
    if other_id is not None and str(other_id).strip() != "":
        parts.append(_quote(int(other_id)))
    return _run("move", " ".join(parts))


def _dispatch_cancel(ctx: ActionContext, *, operation_id: Any = None, eid: Any = None) -> dict[str, Any]:
    if _text(eid):
        return _run("cancel", _quote(f"eid={_text(eid)}"))
    return _run("cancel", _quote(int(operation_id)))


def _dispatch_copy(ctx: ActionContext, *, operation_id: Any = None, changes: Any = None) -> dict[str, Any]:
    return _run("copy", " ".join([_quote(int(operation_id)), *_pairs(changes)]))


def _dispatch_export(ctx: ActionContext, *, operation_id: Any = None) -> dict[str, Any]:
    return _run("export", _quote(int(operation_id)))


def _dispatch_result(ctx: ActionContext, *, operation_id: Any = None, result_hex: Any = None) -> dict[str, Any]:
    return _run("result", f"{_quote(int(operation_id))} {_quote(''.join(_text(result_hex).split()))}")


def _dispatch_euicc_list(ctx: ActionContext) -> dict[str, Any]:
    return _run("euicc", "list")


def _dispatch_overview(ctx: ActionContext, *, eid: Any = None) -> dict[str, Any]:
    """The store as data for the Local eIM page; no card, no change."""
    from SCP11.eim_local.engine.overview import build_overview

    return build_overview(eid=_text(eid))


def _dispatch_op_detail(ctx: ActionContext, *, operation_id: Any = None) -> dict[str, Any]:
    """One operation as data: parameters, timeline, package bytes, result."""
    from SCP11.eim_local.engine.overview import operation_detail
    from SCP11.eim_local.engine.service import LocalEimError
    from SCP11.eim_local.engine.store import StoreError

    try:
        return operation_detail(None, int(operation_id))
    except (LocalEimError, StoreError) as error:
        raise ValueError(str(error)) from error


def _dispatch_euicc_show(ctx: ActionContext, *, eid: Any = None) -> dict[str, Any]:
    return _run("euicc", _quote(_text(eid)))


def _dispatch_euicc_read(ctx: ActionContext, *, reader: Any = None) -> dict[str, Any]:
    return _run("euicc", "READ", reader=_text(reader))


def _dispatch_euicc_register(ctx: ActionContext, *, eid: Any = None, label: Any = None) -> dict[str, Any]:
    return _run("euicc", " ".join(["ADD", _quote(_text(eid)), *([_quote(_text(label))] if _text(label) else [])]))


def _dispatch_euicc_set(ctx: ActionContext, *, eid: Any = None, changes: Any = None) -> dict[str, Any]:
    return _run("euicc", " ".join(["SET", _quote(_text(eid)), *_pairs(changes)]))


def _dispatch_euicc_remove(ctx: ActionContext, *, eid: Any = None, confirm: Any = None) -> dict[str, Any]:
    if not confirm:
        raise ValueError("Tick Confirm: removing a record also deletes its operations.")
    return _run("euicc", f"REMOVE {_quote(_text(eid))}")


def _dispatch_identity_show(ctx: ActionContext) -> dict[str, Any]:
    return _run("identity", "show")


def _dispatch_identity_new(ctx: ActionContext, *, eim_id: Any = None, eim_fqdn: Any = None) -> dict[str, Any]:
    parts = ["NEW"]
    if _text(eim_id):
        parts.append(_quote(_text(eim_id)))
        if _text(eim_fqdn):
            parts.append(_quote(_text(eim_fqdn)))
    return _run("identity", " ".join(parts))


def _dispatch_associate(ctx: ActionContext, *, reader: Any = None, confirm: Any = None, public_key: Any = None,
                        no_reset: Any = None, setup: Any = None) -> dict[str, Any]:
    if not confirm:
        raise ValueError("Tick Confirm: ASSOCIATE resets the card's eIM configuration before AddInitialEim.")
    parts = ["--yes"]
    if _text(setup):
        parts.append(_quote(f"setup={_text(setup)}"))
    if public_key:
        parts.append("--public-key")
    if no_reset:
        parts.append("--no-reset")
    return _run("associate", " ".join(parts), reader=_text(reader))


def _dispatch_associate_choices(ctx: ActionContext) -> dict[str, Any]:
    return _run("associate", "CHOICES")


def _dispatch_associate_handover(ctx: ActionContext, *, reader: Any = None, confirm: Any = None, eim_id: Any = None,
                                 eim_fqdn: Any = None, eim_id_type: Any = None, sign: Any = None, sign_form: Any = None,
                                 tls: Any = None, tls_form: Any = None, counter_value: Any = None, ci_pkid: Any = None,
                                 indirect: Any = None, protocols: Any = None, no_reset: Any = None) -> dict[str, Any]:
    if not confirm:
        raise ValueError("Tick Confirm: HANDOVER resets the card's eIM configuration and binds the card to another eIM.")
    parts = ["HANDOVER", "--yes", _quote(f"eim_id={_text(eim_id)}"), _quote(f"sign={_text(sign)}")]
    if _text(eim_fqdn):
        parts.append(_quote(f"fqdn={_text(eim_fqdn)}"))
    if _text(eim_id_type) and _text(eim_id_type) != "auto":
        parts.append(_quote(f"eim_id_type={_text(eim_id_type)}"))
    if _text(tls):
        parts.append(_quote(f"tls={_text(tls)}"))
    if _text(sign_form) == "public_key":
        parts.append("--public-key")
    if _text(tls_form) == "public_key":
        parts.append("--tls-key")
    if counter_value is not None and str(counter_value).strip() != "":
        parts.append(f"counter={int(counter_value)}")
    if _text(ci_pkid):
        parts.append(_quote(f"ci_pkid={_text(ci_pkid)}"))
    parts.append("indirect=on" if indirect else "indirect=off")
    if _text(protocols):
        parts.append(_quote(f"protocols={_text(protocols)}"))
    if no_reset:
        parts.append("--no-reset")
    return _run("associate", " ".join(parts), reader=_text(reader))


def _dispatch_service_status(ctx: ActionContext) -> dict[str, Any]:
    return _run("serve", "status")


def _dispatch_service_start(ctx: ActionContext, *, port: Any = None, host: Any = None, tls: Any = None,
                            tls_port: Any = None, smdp_tls_port: Any = None,
                            smds_tls_port: Any = None) -> dict[str, Any]:
    parts = ["start"]
    if port is not None and str(port).strip() != "":
        parts.append(_quote(f"port={int(port)}"))
    if _text(host):
        parts.append(_quote(f"host={_text(host)}"))
    if _text(tls_port):
        parts.append(_quote(f"tls_port={_text(tls_port)}"))
    if _text(smdp_tls_port):
        parts.append(_quote(f"smdp_tls_port={_text(smdp_tls_port)}"))
    if _text(smds_tls_port):
        parts.append(_quote(f"smds_tls_port={_text(smds_tls_port)}"))
    if tls:
        parts.append("--tls")
    return _run("serve", " ".join(parts))


def _dispatch_service_restart(ctx: ActionContext) -> dict[str, Any]:
    return _run("serve", "restart")


_TLS_SETUP_OPTIONS = ("fqdn", "layout", "ca_layout", "registered_id", "cn", "chain", "trust", "curve", "san",
                      "validity", "ski", "ca_basic_constraints", "server_auth", "send", "versions", "ciphers",
                      "client_auth", "client_ca", "sni")


def _dispatch_tls_setup_new(ctx: ActionContext, *, name: Any = None, then: Any = None, confirm: Any = None,
                            reader: Any = None, replace: Any = None, force: Any = None,
                            **options: Any) -> dict[str, Any]:
    parts = ["new", _quote(_text(name))]
    for key in _TLS_SETUP_OPTIONS:
        value = options.get(key)
        if isinstance(value, bool):
            parts.append(f"{key}={'on' if value else 'off'}")
        elif _text(value):
            parts.append(_quote(f"{key}={_text(value)}"))
    if replace:
        parts.append("--replace")
    if force:
        parts.append("--force")
    step = _text(then) or "build"
    if step == "apply" and not confirm:
        raise ValueError("Tick Confirm: Build, use and associate resets the card's eIM configuration.")
    if step == "use":
        parts.append("--use")
    elif step == "apply":
        parts.extend(["--apply", "--yes"])
    return _run("tls_setup", " ".join(parts), reader=_text(reader) if step == "apply" else None)


def _dispatch_tls_setup_list(ctx: ActionContext) -> dict[str, Any]:
    return _run("tls_setup", "list")


def _dispatch_tls_setup_show(ctx: ActionContext, *, name: Any = None) -> dict[str, Any]:
    return _run("tls_setup", "show " + _quote(_text(name)))


def _dispatch_tls_setup_use(ctx: ActionContext, *, name: Any = None, associate: Any = None, confirm: Any = None,
                            reader: Any = None) -> dict[str, Any]:
    parts = ["use", _quote(_text(name) or "identity")]
    if associate:
        if not confirm:
            raise ValueError("Tick Confirm: Associate the card resets its eIM configuration.")
        parts.extend(["--associate", "--yes"])
    return _run("tls_setup", " ".join(parts), reader=_text(reader) if associate else None)


def _dispatch_tls_setup_remove(ctx: ActionContext, *, name: Any = None, force: Any = None) -> dict[str, Any]:
    return _run("tls_setup", "remove " + _quote(_text(name)) + (" --force" if force else ""))


def _dispatch_tls_setup_client_cert(ctx: ActionContext, *, name: Any = None, common_name: Any = None) -> dict[str, Any]:
    parts = ["client-cert", _quote(_text(name))]
    if _text(common_name):
        parts.append(_quote(f"cn={_text(common_name)}"))
    return _run("tls_setup", " ".join(parts))


# What a leaf may set; the form's "setup" choice leaves the option out, which keeps the setup's own value.
_TLS_LEAF_OPTIONS = ("cn", "san", "registered_id", "layout", "validity", "ski", "server_auth", "curve", "send")


def _dispatch_tls_leaf_new(ctx: ActionContext, *, setup: Any = None, name: Any = None, use: Any = None,
                           replace: Any = None, text: Any = None, **options: Any) -> dict[str, Any]:
    parts = ["leaf", _quote(_text(setup)), "new", _quote(_text(name))]
    for key in _TLS_LEAF_OPTIONS:
        value = _text(options.get(key))
        if value and value != "setup":
            parts.append(_quote(f"{key}={value}"))
    if str(text or "").strip():
        # The text travels in the request; the verb's text=<file> is for a shell line only.
        parts.append(_quote("lines=" + str(text)))
    if replace:
        parts.append("--replace")
    if use:
        parts.append("--use")
    return _run("tls_setup", " ".join(parts))


def _certificate_text_source(setup: Any, name: Any, certificate: Any, text: Any, model: Any = None) -> tuple[Any, str]:
    """The certificate text a request points at, parsed, and what to call it.

    A leaf of a setup, a certificate in the eIM certificate store, a text, or
    an editor's rows. Nothing here opens a file named in the request.
    """
    import json
    from pathlib import Path

    from SCP11.eim_local.engine import cert_spec, tls_setup
    from SCP11.eim_local.engine.service import LocalEim

    if _text(model):
        try:
            rows = json.loads(str(model))
        except json.JSONDecodeError as error:
            raise ValueError(f"The editor's rows are not JSON: {error}") from error
        return cert_spec.from_model(rows), "The editor's rows"
    if len(str(text or "").strip()) > 0:
        return cert_spec.parse_text(str(text)), "The text given"
    if _text(certificate):
        parsed = cert_spec.parse_text(tls_setup.reference_text(_text(certificate), stored_only=True))
        return parsed, f"Stored certificate {_text(certificate)}"
    if _text(setup) and _text(name):
        parsed = cert_spec.parse_text(tls_setup.leaf_text(Path(LocalEim().directory), _text(setup), _text(name)))
        return parsed, f"Leaf {_text(name)} of TLS setup {_text(setup)}"
    return cert_spec.CertificateSpec(), "No certificate"


def _dispatch_tls_leaf_text(ctx: ActionContext, *, setup: Any = None, name: Any = None, certificate: Any = None,
                            text: Any = None) -> dict[str, Any]:
    """A leaf, a stored certificate or a text as certificate text; no card, no change."""
    from SCP11.eim_local.engine import cert_spec

    spec, title = _certificate_text_source(setup, name, certificate, text)
    canonical = cert_spec.to_text(spec)
    if canonical:
        return {"lines": [f"[*] {title} as text:", *(f"    {line}" for line in canonical.splitlines())]}
    return {"lines": [f"[*] {title}: nothing is written, so a leaf's options decide its subject and extensions."]}


def _dispatch_tls_leaf_rows(ctx: ActionContext, *, setup: Any = None, name: Any = None, certificate: Any = None,
                            text: Any = None, model: Any = None) -> dict[str, Any]:
    """What the Leaf editor works on: a certificate text as rows, the text of rows, and what rows can hold.

    The page keeps no parser of its own: it sends a source and gets the
    rows, or sends rows and gets the text a leaf is issued from. The answer
    also lists the setup's leaves, for the editor's Start from.
    """
    from pathlib import Path

    from SCP11.eim_local.engine import cert_spec, tls_setup
    from SCP11.eim_local.engine.service import LocalEim

    spec, title = _certificate_text_source(setup, name, certificate, text, model)
    canonical = cert_spec.to_text(spec)
    leaves: list[dict[str, Any]] = []
    if _text(setup):
        directory = Path(LocalEim().directory)
        served = tls_setup.served_leaf(tls_setup.load_setup(directory, _text(setup)))
        leaves = [{"name": variant.name, "sha256": variant.sha256, "served": variant.name == served}
                  for variant in tls_setup.list_leaves(directory, _text(setup))]
    subject = "left to the options" if spec.subject is None else f"{sum(len(rdn) for rdn in spec.subject)} attribute(s)"
    extensions = "left to the options" if spec.extensions is None else f"{len(spec.extensions)} extension(s)"
    return {"lines": [f"[*] {title} as rows: subject {subject}, extensions {extensions}."], "text": canonical,
            "model": cert_spec.to_model(spec), "catalogue": cert_spec.catalogue(), "leaves": leaves}


def _dispatch_tls_leaf_list(ctx: ActionContext, *, setup: Any = None) -> dict[str, Any]:
    return _run("tls_setup", "leaf " + _quote(_text(setup)))


def _dispatch_tls_leaf_show(ctx: ActionContext, *, setup: Any = None, name: Any = None,
                            der: Any = None) -> dict[str, Any]:
    return _run("tls_setup", f"leaf {_quote(_text(setup))} show {_quote(_text(name))}" + (" --der" if der else ""))


def _dispatch_tls_leaf_use(ctx: ActionContext, *, setup: Any = None, name: Any = None, then: Any = None,
                           confirm: Any = None, reader: Any = None) -> dict[str, Any]:
    parts = ["leaf", _quote(_text(setup)), "use", _quote(_text(name))]
    step = _text(then) or "serve"
    if step == "associate":
        if not confirm:
            raise ValueError("Tick Confirm: Associate the card resets its eIM configuration.")
        parts.extend(["--associate", "--yes"])
    elif step == "serve_only":
        parts.append("--serve-only")
    return _run("tls_setup", " ".join(parts), reader=_text(reader) if step == "associate" else None)


def _dispatch_tls_leaf_remove(ctx: ActionContext, *, setup: Any = None, name: Any = None) -> dict[str, Any]:
    return _run("tls_setup", f"leaf {_quote(_text(setup))} remove {_quote(_text(name))}")


def _dispatch_tls_results(ctx: ActionContext, *, setup: Any = None, rows: Any = None,
                          count: Any = None) -> dict[str, Any]:
    parts = ["results"]
    if _text(setup):
        parts.append(_quote(_text(setup)))
    if rows:
        parts.append("--rows")
        if count:
            parts.append(f"n={int(count)}")
    return _run("tls_setup", " ".join(parts))


def _dispatch_service_stop(ctx: ActionContext) -> dict[str, Any]:
    return _run("serve", "stop")


def _dispatch_traffic(ctx: ActionContext, *, count: Any = None, eid: Any = None, operation_id: Any = None,
                      brief: Any = None, hex_bodies: Any = None) -> dict[str, Any]:
    parts = [str(int(count))] if count is not None and str(count).strip() != "" else []
    if _text(eid):
        parts.append(_quote(f"eid={_text(eid)}"))
    if operation_id is not None and str(operation_id).strip() != "":
        parts.append(f"op={int(operation_id)}")
    if brief:
        parts.append("--brief")
    if hex_bodies:
        parts.append("--hex")
    return _run("traffic", " ".join(parts))


def _dispatch_deliver(ctx: ActionContext, *, reader: Any = None, once: Any = None) -> dict[str, Any]:
    return _run("deliver", "--once" if once else "", reader=_text(reader))


def _dispatch_inject(ctx: ActionContext, *, eid: Any = None, target: Any = None, binding: Any = None,
                     once: Any = None) -> dict[str, Any]:
    """INJECT: no reader is opened, the IPA that listens holds the card."""
    tokens = [_quote(_text(eid))] if _text(eid) else []
    if _text(target):
        tokens.append("target=" + _quote(_text(target)))
    if _text(binding):
        tokens.append("binding=" + _quote(_text(binding)))
    if _flag(once):
        tokens.append("--once")
    return _run("inject", " ".join(tokens))


def _dispatch_inject_cert(ctx: ActionContext) -> dict[str, Any]:
    """INJECT-CERT: writes into the Local eIM store only, and no reader is opened."""
    return _run("inject_cert", "")


def _sequence_numbers(text: Any) -> list[str]:
    """seqNumbers from a field: digits separated by spaces or commas, nothing else."""
    tokens = _text(text).replace(",", " ").split()
    if any(not token.isdigit() for token in tokens):
        raise ValueError("Sequence numbers are whole numbers, separated by spaces.")
    return tokens


def _dispatch_notifications(ctx: ActionContext, *, eid: Any = None) -> dict[str, Any]:
    """NOTIFICATIONS: reads the store, no reader and no network."""
    return _run("notifications", _quote(_text(eid)) if _text(eid) else "")


def _dispatch_notifications_send(ctx: ActionContext, *, eid: Any = None, seq_numbers: Any = None) -> dict[str, Any]:
    """NOTIFICATIONS SEND: posts to the Notification Receivers the Notifications name; no reader is opened."""
    tokens = ["SEND", *([_quote(_text(eid))] if _text(eid) else []), *_sequence_numbers(seq_numbers)]
    return _run("notifications", " ".join(tokens))


def _dispatch_settings(ctx: ActionContext, *, changes: Any = None) -> dict[str, Any]:
    return _run("settings", " ".join(_pairs(changes)))


def _dispatch_package_import(ctx: ActionContext, *, source: Any = None, eid: Any = None, plan: Any = None,
                             reader: Any = None) -> dict[str, Any]:
    parts = [_quote(_text(source))]
    if _text(eid):
        parts.append(_quote(_text(eid)))
    if plan:
        parts.append("--plan")
    return _run("package_import", " ".join(parts),
                reader=_text(reader) if _import_reads_card({"eid": eid}) else None)


def _dispatch_smdp_profiles(ctx: ActionContext, *, matching_id: Any = None, profile_path: Any = None,
                            remove: Any = None) -> dict[str, Any]:
    if not _text(matching_id):
        return _run("smdp_profile", "")
    target = "-" if remove else _text(profile_path)
    if not target:
        raise ValueError("Give a profile file, or tick Remove.")
    return _run("smdp_profile", f"{_quote(_text(matching_id))} {_quote(target)}")


def _dispatch_smds_events(ctx: ActionContext, *, eid: Any = None) -> dict[str, Any]:
    """SMDS / SMDS LIST: reads the store and the SGP.26 bundle; no reader, no network."""
    return _run("smds", f"LIST {_quote(_text(eid))}" if _text(eid) else "")


def _dispatch_smds_register(ctx: ActionContext, *, eid: Any = None, event_id: Any = None, rsp: Any = None,
                            event_type: Any = None) -> dict[str, Any]:
    """SMDS REGISTER: writes one Event Record into the store; no reader is opened."""
    if not _text(eid):
        raise ValueError("Give the EID of the eUICC the Event Record is for.")
    tokens = ["REGISTER", _quote(_text(eid))]
    if _text(event_id):
        tokens.append(_quote("event=" + _text(event_id)))
    if _text(rsp):
        tokens.append(_quote("rsp=" + _text(rsp)))
    if _text(event_type):
        tokens.append(_quote("type=" + _text(event_type)))
    return _run("smds", " ".join(tokens))


def _dispatch_smds_delete(ctx: ActionContext, *, eid: Any = None, event_id: Any = None) -> dict[str, Any]:
    if not _text(eid) or not _text(event_id):
        raise ValueError("Give the EID and the EventID of the Event Record to delete.")
    return _run("smds", f"DELETE {_quote(_text(eid))} {_quote(_text(event_id))}")


def _dispatch_smds_address(ctx: ActionContext, *, address: Any = None) -> dict[str, Any]:
    """SMDS ADDRESS: shows the name, or sets it and restarts a running service."""
    return _run("smds", f"ADDRESS {_quote(_text(address))}" if _text(address) else "ADDRESS")


# ----------------------------------------------------------------------
# Specs
# ----------------------------------------------------------------------


def _reader() -> ActionField:
    return ActionField(name="reader", label="Reader", kind="reader", required=False, default="",
                       help="The card in this reader (empty: the first reader).")


def _operation_id() -> ActionField:
    return ActionField(name="operation_id", label="Operation", kind="int", required=True, min_value=1,
                       help="The operation number OPS lists.")


def _changes(label: str, help_text: str) -> ActionField:
    return ActionField(name="changes", label=label, kind="text", required=False, multiline=True,
                       placeholder="iccid=8988211111111111129\nrollback=on", help=help_text)


def _spec(suffix: str, title: str, description: str, dispatcher: Callable[..., Any],
          inputs: tuple[ActionField, ...] = (), *, card: bool = False, tags: tuple[str, ...] = (),
          uses_reader: Callable[[dict[str, Any]], bool] | None = None) -> ActionSpec:
    return ActionSpec(
        id=f"eim_local.{suffix}",
        subsystem=SUBSYSTEM,
        title=title,
        description=description,
        inputs=inputs,
        output_kind="markdown",
        dispatcher=dispatcher,
        requires_card=card,
        tags=("eim", "queue", *tags),
        uses_reader=uses_reader,
    )


SPECS: tuple[ActionSpec, ...] = (
    _spec(
        "op_queue", "Queue operation",
        "Queue one operation for an eUICC (or the card in the reader). It is signed when an IPA takes it: "
        "the background service (the eSIM Management console's DOWNLOAD or another IPA's poll) or Deliver. Failed "
        "preconditions are warnings; Plan only shows what would be queued.",
        _dispatch_queue,
        (
            ActionField(name="operation", label="Operation", kind="enum", required=True,
                        default="LIST-PROFILES", choices=OPERATION_CHOICES),
            ActionField(name="eid", label="EID", required=False,
                        help="32 digits; empty takes the card in the reader."),
            ActionField(name="value", label="Value", required=False,
                        help="ICCID, activation code, address, eimId, on/off or items, by operation."),
            ActionField(name="params", label="More parameters", kind="text", required=False, multiline=True,
                        placeholder="rollback=on", help="key=value, one per line."),
            ActionField(name="at", label="Not before (UTC)", required=False, placeholder="2026-11-06T08:00Z"),
            ActionField(name="retries", label="Max retries", kind="int", required=False, min_value=0),
            ActionField(name="fault", label="Inject fault", kind="enum", required=False, default="",
                        choices=FAULT_CHOICES),
            ActionField(name="raw", label="Raw items (hex)", kind="hex", required=False,
                        help="Replaces the built PSMO / eCO items."),
            ActionField(name="eid_file", label="EID list file", kind="path", required=False,
                        help="One EID per line: queue for each."),
            ActionField(name="first", label="Front of the queue", kind="bool", required=False, default=False),
            ActionField(name="plan", label="Plan only", kind="bool", required=False, default=False),
            _reader(),
        ),
        tags=("new",),
        uses_reader=_queue_reads_card,
    ),
    _spec(
        "op_list", "Operations", "Pending, completed or all operations, newest first.", _dispatch_list,
        (
            ActionField(name="scope", label="Show", kind="enum", required=False, default="pending",
                        choices=["pending", "completed", "all"]),
            ActionField(name="eid", label="EID", required=False),
            ActionField(name="type", label="Type", required=False, placeholder="ENABLE_PROFILE"),
            ActionField(name="limit", label="Limit", kind="int", required=False, default=50, min_value=1),
        ),
    ),
    _spec("op_show", "Operation detail", "One operation: parameters, timeline, served package and result.",
          _dispatch_show, (_operation_id(),)),
    _spec("op_edit", "Edit operation",
          "Change a CREATED operation: parameters (key=value), type=, raw=, at=, retries=, fault=; a key with no "
          "value removes it. A SENT operation takes only retries=.",
          _dispatch_edit, (_operation_id(), _changes("Changes", "key=value, one per line."))),
    _spec("op_move", "Move operation", "Reorder a CREATED operation in its eUICC's queue.", _dispatch_move,
          (
              _operation_id(),
              ActionField(name="where", label="Where", kind="enum", required=True, default="first",
                          choices=["first", "last", "up", "down", "before", "after"]),
              ActionField(name="other_id", label="Other operation", kind="int", required=False, min_value=1,
                          help="For before / after."),
          )),
    _spec("op_cancel", "Cancel operation",
          "Cancel a queued operation, or every queued one of an EID. A SENT one is given up (the card may "
          "have run it).", _dispatch_cancel,
          (
              ActionField(name="operation_id", label="Operation", kind="int", required=False, min_value=1),
              ActionField(name="eid", label="Or all of EID", required=False),
          )),
    _spec("op_copy", "Copy operation", "Queue a copy of any operation, optionally changed (a retry).",
          _dispatch_copy, (_operation_id(), _changes("Changes", "key=value, one per line; optional."))),
    _spec("op_export", "Export operation",
          "Sign a CREATED operation for another IPA: the package and its STORE DATA APDUs.", _dispatch_export,
          (_operation_id(),)),
    _spec("op_result", "Import result", "Close an operation with an EimPackageResult obtained elsewhere.",
          _dispatch_result,
          (_operation_id(), ActionField(name="result_hex", label="Result (hex)", kind="text", required=True,
                                        multiline=True))),
    _spec("package_import", "Import package document",
          "Queue what an eIM package document (a template or a hotfolder file, or every file of a folder) "
          "stands for: a PSMO or eCO list, an IPA eUICC data request or a profile download trigger.",
          _dispatch_package_import,
          (ActionField(name="source", label="Document or folder", kind="path", required=True),
           ActionField(name="eid", label="EID", required=False, help="Empty takes the card in the reader."),
           ActionField(name="plan", label="Plan only", kind="bool", required=False, default=False),
           _reader()), uses_reader=_import_reads_card),
    _spec("euicc_list", "eUICCs", "Every eUICC the Local eIM knows: profiles, last poll, queue.",
          _dispatch_euicc_list),
    dataclasses.replace(
        _spec("overview", "Local eIM overview",
              "What the Local eIM page shows, as data: the eIM identity with its certificates, the chains it "
              "serves, the service, the queue rules, the eUICC records and one eUICC in detail. Reads the "
              "store only.", _dispatch_overview,
              (ActionField(name="eid", label="EID", required=False),), tags=("read-only",)),
        output_kind="json",
    ),
    dataclasses.replace(
        _spec("op_detail", "Operation as data",
              "One operation for the Local eIM page: parameters with their specification, timeline, the "
              "package bytes (served, or fixed so far) and the result. Reads the store only.",
              _dispatch_op_detail,
              (ActionField(name="operation_id", label="Operation", kind="int", required=True, min_value=1),),
              tags=("read-only",)),
        output_kind="json",
    ),
    _spec("euicc_show", "eUICC record", "One record: token, counter, sequence number, profiles, eIMs, queue.",
          _dispatch_euicc_show, (ActionField(name="eid", label="EID", required=True),)),
    _spec("euicc_read", "Read card into record",
          "GetEID, GetCerts, the profile list, the eIM configuration and the configured addresses of the card "
          "in the reader, into its record.", _dispatch_euicc_read, (_reader(),), card=True),
    _spec("euicc_register", "Register eUICC", "Add a record without touching a card.", _dispatch_euicc_register,
          (ActionField(name="eid", label="EID", required=True), ActionField(name="label", label="Label", required=False))),
    _spec("euicc_set", "Edit eUICC record",
          "Set label, association_token, counter_value, seq_number or associated by hand.", _dispatch_euicc_set,
          (ActionField(name="eid", label="EID", required=True),
           _changes("Changes", "key=value, one per line, e.g. counter_value=40."))),
    _spec("euicc_remove", "Remove eUICC record", "Delete a record and its operations.", _dispatch_euicc_remove,
          (ActionField(name="eid", label="EID", required=True),
           ActionField(name="confirm", label="Confirm", kind="bool", required=True, default=False))),
    _spec("identity_show", "eIM identity", "eimId, FQDN, signing and TLS certificates of the Local eIM.",
          _dispatch_identity_show),
    _spec("identity_new", "New eIM identity",
          "Generate a P-256 signing key with a signing and a TLS certificate.", _dispatch_identity_new,
          (ActionField(name="eim_id", label="eimId", required=False, placeholder="1.3.6.1.4.1.32473.999.10.124"),
           ActionField(name="eim_fqdn", label="FQDN", required=False, placeholder="eim.yggdrasim.local"))),
    _spec("associate", "Associate card",
          "eUICCMemoryReset of the eIM configuration, then AddInitialEim with this identity, on the card in the "
          "reader: the eIM FQDN and the TLS trust come from the TLS setup in use. Every other eIM leaves the card.",
          _dispatch_associate,
          (_reader(),
           ActionField(name="confirm", label="Confirm", kind="bool", required=True, default=False),
           ActionField(name="setup", label="TLS setup", required=False, default="",
                       help="The TLS setup whose eIM FQDN and trust the card is given and remembered with; identity: "
                            "the identity's own certificate and FQDN; empty: the setup this card was associated with "
                            "before, else the one in use. Association choices lists them."),
           ActionField(name="public_key", label="Public key instead of certificate", kind="bool", required=False,
                       default=False),
           ActionField(name="no_reset", label="Skip the reset", kind="bool", required=False, default=False)),
          card=True),
    _spec("associate_choices", "Association choices",
          "What Associate card can carry: the identity, every TLS setup with its eIM FQDN and trust, and the stored "
          "certificates Hand over card takes.", _dispatch_associate_choices),
    _spec("associate_handover", "Hand over card",
          "eUICCMemoryReset of the eIM configuration, then AddInitialEim with another eIM's stored certificates "
          "(eIM certificate store), eimId, FQDN and counter. The Local eIM holds no key for that eIM, so its own "
          "packages are refused by the card until Associate card runs again.", _dispatch_associate_handover,
          (_reader(),
           ActionField(name="confirm", label="Confirm", kind="bool", required=True, default=False),
           ActionField(name="eim_id", label="eimId", required=True, placeholder="2.999.1"),
           ActionField(name="eim_fqdn", label="eimFqdn", required=False, placeholder="eim.example.test",
                       help="Left out when eimIdType is fqdn (the eimId is the FQDN)."),
           ActionField(name="eim_id_type", label="eimIdType", kind="enum", required=False, default="auto",
                       choices=("auto", "oid", "fqdn", "proprietary")),
           ActionField(name="sign", label="eIM certificate", required=True,
                       placeholder="name in the eIM certificate store",
                       help="eimPublicKeyData: the eIM's signing certificate, from the store."),
           ActionField(name="sign_form", label="eimPublicKeyData", kind="enum", required=False, default="certificate",
                       choices=("certificate", "public_key"),
                       help="certificate sends it whole (eimCertificate); public_key its SubjectPublicKeyInfo (eimPublicKey)."),
           ActionField(name="tls", label="TLS trust certificate", required=False, default="",
                       placeholder="name in the eIM certificate store, or none",
                       help="trustedPublicKeyDataTls: the eIM's TLS certificate or a CA of its chain; empty leaves it out."),
           ActionField(name="tls_form", label="trustedPublicKeyDataTls", kind="enum", required=False,
                       default="certificate", choices=("certificate", "public_key")),
           ActionField(name="counter_value", label="counterValue", kind="int", required=False, default=0, min_value=0,
                       max_value=0x7FFFFF),
           ActionField(name="ci_pkid", label="euiccCiPKId", required=False, default="",
                       help="Hex, or card: the first CI Public Key Identifier the card lists for signing."),
           ActionField(name="indirect", label="indirectProfileDownload", kind="bool", required=False, default=False),
           ActionField(name="protocols", label="eimSupportedProtocol", required=False, default="eimRetrieveHttps",
                       help="Comma separated bit names; eimRetrieveHttps by default."),
           ActionField(name="no_reset", label="Skip the reset", kind="bool", required=False, default=False)),
          card=True),
    _spec("service_status", "Service status",
          "Whether the background ESipa service (with the local SM-DP+ and SM-DS) is running and where.",
          _dispatch_service_status),
    _spec("service_start", "Start service",
          "Run the ESipa service in the background: the eSIM Management console's DOWNLOAD and any other IPA "
          "reach it by the eIM FQDN and the SM-DP+ address.", _dispatch_service_start,
          (ActionField(name="port", label="Port", kind="int", required=False, default=8743, min_value=1,
                       max_value=65535),
           ActionField(name="host", label="Host", required=False, default="127.0.0.1"),
           ActionField(name="tls_port", label="Card TLS port", required=False, default="auto",
                       help="The listener a card's IPAe reaches: auto (the next port), a port number, or off."),
           ActionField(name="smdp_tls_port", label="SM-DP+ card TLS port", required=False, default="auto",
                       help="The listener a card's IPAe reaches the local SM-DP+ on for a direct download: "
                            "auto (two ports up), a port number, or off."),
           ActionField(name="smds_tls_port", label="SM-DS card TLS port", required=False, default="auto",
                       help="The listener a card's IPAe reaches the local SM-DS on when it retrieves its Event "
                            "Records itself: auto (four ports up), a port number, or off."),
           ActionField(name="tls", label="TLS", kind="bool", required=False, default=False))),
    _spec("service_restart", "Restart service",
          "Restart the background service on the same ports, serving the TLS setup in use.",
          _dispatch_service_restart),
    _spec("service_stop", "Stop service", "Stop the background ESipa service.", _dispatch_service_stop),
    _spec("traffic", "Traffic",
          "The exchanges the service answered, oldest first: who asked over which TLS chain, what the request "
          "said and what the eIM answered, by name and value (ESipa GetEimPackage, ProvideEimPackageResult, "
          "HandleNotification; the ES9+ functions of the local SM-DP+).", _dispatch_traffic,
          (ActionField(name="count", label="Exchanges", kind="int", required=False, default=20, min_value=1,
                       max_value=500, help="How many of the most recent exchanges to show."),
           ActionField(name="eid", label="EID", required=False, default="", help="Only this eUICC's exchanges."),
           ActionField(name="operation_id", label="Operation", kind="int", required=False, min_value=1,
                       help="Only the exchanges that served or closed this operation."),
           ActionField(name="brief", label="One line each", kind="bool", required=False, default=False),
           ActionField(name="hex_bodies", label="Show the bodies in hex", kind="bool", required=False,
                       default=False))),
    _spec("tls_setup_new", "New TLS setup",
          "Build a TLS chain for the card-facing listener and choose what AddInitialEim tells the card to trust "
          "(trustedPublicKeyDataTls). Then: build only, serve it, or serve it and re-run Associate card.",
          _dispatch_tls_setup_new,
          (ActionField(name="name", label="Name", required=True, placeholder="ca-chain"),
           ActionField(name="chain", label="Chain", kind="enum", required=False, default="self",
                       choices=("self", "root", "intermediate"),
                       help="self: a self-signed leaf; root: root CA and leaf; intermediate: root, intermediate, leaf."),
           ActionField(name="trust", label="Card trusts", kind="enum", required=False, default="leaf",
                       choices=("leaf", "leaf_key", "root", "intermediate", "none"),
                       help="leaf_key sends the leaf's public key (trustedEimPkTls); none leaves the member out."),
           ActionField(name="curve", label="Key", kind="enum", required=False, default="p256",
                       choices=("p256", "p384", "brainpoolp256r1", "ed25519")),
           ActionField(name="send", label="Listener sends", kind="enum", required=False, default="chain",
                       choices=("leaf", "chain", "full"),
                       help="leaf alone; chain: leaf and intermediate; full: the root as well."),
           ActionField(name="versions", label="TLS versions", kind="enum", required=False, default="1.2+",
                       choices=("1.2+", "1.2", "1.3")),
           ActionField(name="validity", label="Leaf validity", kind="enum", required=False, default="valid",
                       choices=("valid", "expired", "not_yet_valid")),
           ActionField(name="fqdn", label="eIM FQDN", required=False, default="",
                       help="The eIM FQDN this setup stands for: AddInitialEim carries it as eimFqdn and the leaf is "
                            "issued for it. Empty: the identity's. A name outside RFC 2606 reaches a real host."),
           ActionField(name="layout", label="Leaf layout", required=False, default="",
                       help="A stored certificate (eIM certificate store) or file whose subject and extension layout "
                            "the leaf takes; fresh keys, the setup's FQDN and the identity's eimId replace its own."),
           ActionField(name="ca_layout", label="CA layout", required=False, default="",
                       help="The same for the root and intermediate CA certificates."),
           ActionField(name="registered_id", label="SAN registeredID", kind="enum", required=False, default="auto",
                       choices=("auto", "on", "off"),
                       help="auto: a shaped leaf carries the eimId as registeredID where the reference had one, a "
                            "generic leaf none; on: the eimId next to the DNS name; off: a DNS-only SubjectAltName."),
           ActionField(name="cn", label="Leaf CN", kind="enum", required=False, default="auto",
                       choices=("auto", "host", "keep", "eim_id"),
                       help="auto: the reference's CN unless it names its host; host: the setup's FQDN; keep: the "
                            "reference's CN as it is; eim_id: the Local eIM's eimId, with or without a layout."),
           ActionField(name="san", label="Leaf name", required=False, default="",
                       help="Empty: the setup's eIM FQDN; none: no SubjectAltName; anything else names another host."),
           ActionField(name="ski", label="SubjectKeyIdentifier", kind="bool", required=False, default=True),
           ActionField(name="ca_basic_constraints", label="CA BasicConstraints", kind="bool", required=False,
                       default=True),
           ActionField(name="server_auth", label="serverAuth EKU", kind="bool", required=False, default=True),
           ActionField(name="ciphers", label="TLS 1.2 ciphers", required=False, default="",
                       help="OpenSSL cipher list; empty for OpenSSL's default."),
           ActionField(name="client_auth", label="Client authentication", kind="enum", required=False, default="none",
                       choices=("none", "optional", "required"),
                       help="none: server authentication only, as SGP.32 asks; optional: a client certificate is "
                            "asked for and a client without one is served; required: mutual TLS."),
           ActionField(name="client_ca", label="Client CA", required=False, default="",
                       help="Stored certificates or files the client certificates chain to, comma separated; "
                            "empty: the setup's own CA (Client certificate issues one under it)."),
           ActionField(name="sni", label="Server name (SNI)", kind="enum", required=False, default="any",
                       choices=("any", "required"),
                       help="required: only a ClientHello naming the leaf's host is answered."),
           ActionField(name="replace", label="Replace a setup of that name", kind="bool", required=False,
                       default=False),
           ActionField(name="force", label="Force", kind="bool", required=False, default=False,
                       help="Replace a setup that has further leaves or associated cards; its CA goes with it."),
           ActionField(name="then", label="Then", kind="enum", required=False, default="build",
                       choices=("build", "use", "apply"),
                       help="use: serve it now; apply: serve it and Associate card (eIM reset, AddInitialEim)."),
           _reader(),
           ActionField(name="confirm", label="Confirm", kind="bool", required=False, default=False))),
    _spec("tls_setup_list", "TLS setups", "The TLS setups built and the one the card-facing listener serves.",
          _dispatch_tls_setup_list),
    _spec("tls_setup_show", "Show TLS setup", "One TLS setup: its certificates, what the card trusts, what is sent.",
          _dispatch_tls_setup_show, (ActionField(name="name", label="Name", required=True),)),
    _spec("tls_setup_use", "Use TLS setup",
          "Serve a TLS setup on the card-facing listener (identity: the identity's own certificate); with "
          "Associate card the card is told to trust it.", _dispatch_tls_setup_use,
          (ActionField(name="name", label="Name", required=True, default="identity"),
           ActionField(name="associate", label="Associate card", kind="bool", required=False, default=False),
           _reader(),
           ActionField(name="confirm", label="Confirm", kind="bool", required=False, default=False))),
    _spec("tls_setup_remove", "Remove TLS setup", "Delete a TLS setup that is not in use.",
          _dispatch_tls_setup_remove,
          (ActionField(name="name", label="Name", required=True),
           ActionField(name="force", label="Force", kind="bool", required=False, default=False,
                       help="Remove a setup that has further leaves or associated cards; its CA goes with it."))),
    _spec("tls_setup_client_cert", "Client certificate",
          "Issue a TLS client certificate under a setup's own CA, for a client of its mutual-TLS form.",
          _dispatch_tls_setup_client_cert,
          (ActionField(name="name", label="Name", required=True),
           ActionField(name="common_name", label="Common name", required=False, default="",
                       help="Empty: <setup> TLS client."))),
    _spec("tls_leaf_new", "New leaf",
          "Issue a further leaf under a TLS setup's own CA. The setup's name, CA and what the card was told to trust "
          "stay as they are, so a card that trusts the root or the intermediate meets the leaf without a new "
          "Associate card. An option left on setup is the setup's own.",
          _dispatch_tls_leaf_new,
          (ActionField(name="setup", label="TLS setup", required=True),
           ActionField(name="name", label="Leaf", required=True, placeholder="cn-eimid"),
           ActionField(name="cn", label="Leaf CN", kind="enum", required=False, default="setup",
                       choices=("setup", "auto", "host", "keep", "eim_id"),
                       help="host: the setup's FQDN; keep: the layout reference's CN; eim_id: the Local eIM's eimId."),
           ActionField(name="registered_id", label="SAN registeredID", kind="enum", required=False, default="setup",
                       choices=("setup", "auto", "on", "off")),
           ActionField(name="san", label="Leaf name", required=False, default="",
                       help="Empty: the setup's; none: no SubjectAltName; anything else names another host."),
           ActionField(name="layout", label="Leaf layout", required=False, default="",
                       help="Empty: the setup's; none: the generic shape; else a stored certificate or file."),
           ActionField(name="validity", label="Leaf validity", kind="enum", required=False, default="setup",
                       choices=("setup", "valid", "expired", "not_yet_valid")),
           ActionField(name="ski", label="SubjectKeyIdentifier", kind="enum", required=False, default="setup",
                       choices=("setup", "on", "off")),
           ActionField(name="server_auth", label="serverAuth EKU", kind="enum", required=False, default="setup",
                       choices=("setup", "on", "off")),
           ActionField(name="curve", label="Key", kind="enum", required=False, default="setup",
                       choices=("setup", "p256", "p384", "brainpoolp256r1", "ed25519")),
           ActionField(name="send", label="Listener sends", kind="enum", required=False, default="setup",
                       choices=("setup", "leaf", "chain", "full")),
           ActionField(name="text", label="Certificate text", kind="text", required=False, multiline=True,
                       placeholder="subject = CN={host},O=Example Org,C=XX",
                       help="Subject and extension lines, built as written; the options above decide what it leaves "
                            "out. One line each: subject = <RFC 4514 name>, keyUsage = critical, digitalSignature, "
                            "subjectAltName = DNS:{host}, RID:{eim_id}, <object identifier> = DER:<hex>."),
           ActionField(name="replace", label="Replace a leaf of that name", kind="bool", required=False,
                       default=False),
           ActionField(name="use", label="Put it on the setup's name", kind="bool", required=False, default=False,
                       help="Serves it now. A setup that tells the card to trust the leaf itself takes Use leaf."))),
    _spec("tls_leaf_text", "Certificate text",
          "A leaf of a TLS setup, or a stored certificate, as text: its subject and one line per extension, in the "
          "form New leaf takes. A text given here is checked and returned in its canonical form.",
          _dispatch_tls_leaf_text,
          (ActionField(name="setup", label="TLS setup", required=False, default=""),
           ActionField(name="name", label="Leaf", required=False, default="", placeholder="built"),
           ActionField(name="certificate", label="Stored certificate", required=False, default="",
                       help="A name in the eIM certificate store, instead of a leaf."),
           ActionField(name="text", label="Certificate text", kind="text", required=False, multiline=True,
                       help="A text to check, instead of a leaf or a stored certificate."))),
    _spec("tls_leaf_rows", "Leaf editor rows",
          "The data the Leaf editor of the Local eIM page works on: a leaf, a stored certificate or a text as rows, "
          "or the editor's rows as text, with the attribute types and extensions a row can hold.",
          _dispatch_tls_leaf_rows,
          (ActionField(name="setup", label="TLS setup", required=False, default=""),
           ActionField(name="name", label="Leaf", required=False, default=""),
           ActionField(name="certificate", label="Stored certificate", required=False, default=""),
           ActionField(name="text", label="Certificate text", kind="text", required=False, multiline=True),
           ActionField(name="model", label="Editor rows", kind="text", required=False, multiline=True,
                       help="The editor's rows as JSON; the editor sends them."))),
    _spec("tls_leaf_list", "Leaves", "The leaves of a TLS setup and the one on its name.",
          _dispatch_tls_leaf_list, (ActionField(name="setup", label="TLS setup", required=True),)),
    _spec("tls_leaf_show", "Show leaf", "One leaf of a TLS setup: its options, certificate and SHA-256.",
          _dispatch_tls_leaf_show,
          (ActionField(name="setup", label="TLS setup", required=True),
           ActionField(name="name", label="Leaf", required=True),
           ActionField(name="der", label="Print the DER", kind="bool", required=False, default=False,
                       help="The certificate and its public key in hex, as an Update eIM operation takes them."))),
    _spec("tls_leaf_use", "Use leaf",
          "Put a leaf on its TLS setup's name; the running service restarts. A card that trusts the setup's root or "
          "intermediate needs nothing more. A setup that tells the card to trust the leaf itself takes serve_only "
          "(the card is left as it is) or associate (Associate card, which resets its eIM configuration).",
          _dispatch_tls_leaf_use,
          (ActionField(name="setup", label="TLS setup", required=True),
           ActionField(name="name", label="Leaf", required=True, default="built"),
           ActionField(name="then", label="Then", kind="enum", required=False, default="serve",
                       choices=("serve", "serve_only", "associate")),
           _reader(),
           ActionField(name="confirm", label="Confirm", kind="bool", required=False, default=False))),
    _spec("tls_leaf_remove", "Remove leaf", "Delete a leaf that is not on its TLS setup's name.",
          _dispatch_tls_leaf_remove,
          (ActionField(name="setup", label="TLS setup", required=True),
           ActionField(name="name", label="Leaf", required=True))),
    _spec("tls_results", "TLS results",
          "What the card-facing handshakes say about each leaf served: accepted (a full handshake that a request "
          "followed), refused with the client's alert, resumed sessions counted apart.",
          _dispatch_tls_results,
          (ActionField(name="setup", label="TLS setup", required=False, default="", help="Empty: every setup."),
           ActionField(name="rows", label="List the handshakes", kind="bool", required=False, default=False),
           ActionField(name="count", label="Count", kind="int", required=False, default=40, min_value=1,
                       max_value=500, help="How many of the most recent handshakes to list."))),
    _spec("deliver", "Deliver to card",
          "Act as IPAd on the card in the reader until its queue is empty: LoadEuiccPackage, the result, "
          "RemoveNotificationFromList. The Notifications read from the card with a result are then sent to the "
          "SM-DP+ each names.", _dispatch_deliver,
          (_reader(), ActionField(name="once", label="One package only", kind="bool", required=False, default=False)),
          card=True, tags=("destructive",)),
    _spec("inject", "Inject to IPA",
          "Send an eUICC's queue to an IPA that listens for it: the eIM calls ESipa.TransferEimPackage, one eIM "
          "Package per call, and takes the result from the answer (eIM Package Injection, GSMA SGP.32 v1.3 section "
          "3.1.1.2). The IPA is EIM-LISTEN in the eSIM Management console, which prints the target. Plain HTTP on "
          "the loopback, or HTTPS on any address with this eIM's injection client certificate; no reader is used "
          "and a profile download stays queued.", _dispatch_inject,
          (ActionField(name="eid", label="EID", required=False,
                       help="32 digits; empty takes the one eUICC that has an inject target."),
           ActionField(name="target", label="Inject target", required=False, placeholder="http://127.0.0.1:8746",
                       help="The address EIM-LISTEN prints (http://<loopback>:<port> or https://<address>:<port>); "
                            "kept for the eUICC. Empty uses the kept one, none clears it."),
           ActionField(name="binding", label="Binding", kind="enum", required=False, default="asn1",
                       choices=("asn1", "json"), help="The function binding the call uses; kept with the target."),
           ActionField(name="once", label="One package only", kind="bool", required=False, default=False))),
    _spec("inject_cert", "Injection client certificate",
          "The client certificate this eIM presents to an IPA that takes ESipa.TransferEimPackage over HTTPS: made "
          "on first use, then shown with its SHA-256. The IPA authenticates the eIM by it (GSMA SGP.32 v1.3 section "
          "3.1.2.1): its file is the client-ca of EIM-LISTEN.", _dispatch_inject_cert, ()),
    _spec("notifications", "Notifications",
          "The Notifications IPAs handed to this eIM and where each stands: pending, delivered to its Notification "
          "Receiver, failed (not delivered and not tried again by itself), or kept from before the eIM forwarded any "
          "(GSMA SGP.32 v1.3 section 5.14.6, 5.14.7). The eIM holds none back.",
          _dispatch_notifications,
          (ActionField(name="eid", label="EID", required=False, help="32 digits; empty lists every eUICC."),)),
    _spec("notifications_send", "Send Notifications",
          "Send Notifications to the Notification Receivers they name, with ES9+'.HandleNotification over HTTPS "
          "(GSMA SGP.32 v1.3 section 5.7.4). Without sequence numbers the pending ones go; a failed or kept one goes "
          "only when its sequence number is given. What a receiver has taken cannot be taken back.",
          _dispatch_notifications_send,
          (ActionField(name="eid", label="EID", required=False,
                       help="32 digits; empty sends the pending Notifications of every eUICC."),
           ActionField(name="seq_numbers", label="Sequence numbers", required=False, placeholder="7 9",
                       help="seqNumber of each Notification to send, separated by spaces; needs the EID.")),
          tags=("destructive",)),
    _spec("queue_settings", "Queue rules",
          "learn_unknown_eids, recover_lost_results, max_retries, result_verification, tls_keylog, "
          "smds_address.", _dispatch_settings,
          (_changes("Changes", "key=value, one per line; empty shows the rules."),)),
    _spec("smdp_profiles", "Local SM-DP+ profiles",
          "Which profile file the local SM-DP+ serves for a Matching ID.", _dispatch_smdp_profiles,
          (ActionField(name="matching_id", label="Matching ID", required=False),
           ActionField(name="profile_path", label="Profile file", kind="path", required=False),
           ActionField(name="remove", label="Remove", kind="bool", required=False, default=False))),
    _spec("smds_events", "Local SM-DS",
          "The SM-DS this eIM's service runs: the name it answers under, its CERT.DSauth.SIG and the Event Records "
          "it holds (GSMA SGP.22 v3.1 section 3.6). Only an eUICC that trusts the SGP.26 test eSIM CA accepts it.",
          _dispatch_smds_events,
          (ActionField(name="eid", label="EID", required=False,
                       help="32 digits lists the Event Records of that eUICC; empty shows the SM-DS and every "
                            "record."),)),
    _spec("smds_register", "Register SM-DS event",
          "Put an Event Record on file at the local SM-DS for an eUICC, as an SM-DP+ does with ES12.RegisterEvent "
          "(GSMA SGP.22 v3.1 section 5.9.1). A download queued with contact_smds retrieves it, and the EventID is "
          "the Matching ID of the download that follows.", _dispatch_smds_register,
          (ActionField(name="eid", label="EID", required=True, help="32 digits."),
           ActionField(name="event_id", label="EventID", required=False, placeholder="MID-1",
                       help="The Matching ID the SM-DP+ will be asked for; empty makes one up."),
           ActionField(name="rsp", label="RSP Server address", required=False, placeholder="smdpp.example.test",
                       help="The SM-DP+ the Event Record points at; empty is the local SM-DP+."),
           ActionField(name="event_type", label="Event type", kind="enum", required=False, default="download",
                       choices=("download", "rpm"),
                       help="download is a Profile download (eventType 1), rpm an RPM event (eventType 2)."))),
    _spec("smds_delete", "Delete SM-DS event",
          "Take an Event Record off the local SM-DS, as ES12.DeleteEvent does (GSMA SGP.22 v3.1 section 5.9.2). "
          "The local SM-DP+ does this itself when the download a record led to ends.", _dispatch_smds_delete,
          (ActionField(name="eid", label="EID", required=True, help="32 digits."),
           ActionField(name="event_id", label="EventID", required=True))),
    _spec("smds_address", "SM-DS address",
          "The FQDN the local SM-DS answers under: an ES11.InitiateAuthentication that names it is answered by the "
          "SM-DS, any other address by the SM-DP+. Setting it restarts a running service.", _dispatch_smds_address,
          (ActionField(name="address", label="SM-DS address", required=False, placeholder="smds.example.test",
                       help="A host name without scheme, port or path; empty shows the one in use."),)),
)

for _spec_entry in SPECS:
    get_registry().register(_spec_entry)
