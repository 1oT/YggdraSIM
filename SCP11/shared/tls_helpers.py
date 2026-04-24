"""Central gate for insecure / introspection TLS contexts used by SCP11.

Two distinct trust-posture needs exist in the SCP11 tree:

1. **Full unpinned traffic** (request-carrying). Historically used when
   developers set ``verify_tls=False`` on an ES9 client or when the
   transport layer runs against SGP.26 test vectors. This path sends
   real request bodies over an unverified TLS channel. It is a
   foot-gun and must stay behind an explicit opt-in.

2. **Chain introspection** (read-only TOFU bootstrap). Used when the
   client needs to fetch the server's certificate chain so it can
   auto-learn a trust anchor for a freshly-seen FQDN and persist it
   under ``SCP11/<tree>/dynamic_ca/``. No request body is ever sent
   over this context — only the TLS handshake runs, and the socket is
   closed immediately after the peer cert is read. Auto-learn is the
   intended day-one behaviour for new eUICCs / new eIM endpoints, so
   this path is allowed by default and can only be *tightened* for
   locked-down deployments.

The two gates are:

- ``YGGDRASIM_SCP11_ALLOW_INSECURE_TLS`` — opts in to full unpinned
  request traffic. Default: refused. Controls
  :func:`create_insecure_context` and :func:`configure_unpinned_context`.

- ``YGGDRASIM_SCP11_REQUIRE_PINNED_TLS`` — hard-lock that also refuses
  unpinned request traffic even if the ``ALLOW_INSECURE_TLS`` flag is
  set. Intended for CI / fleet deployments where nobody should ever
  downgrade a request.

- ``YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION`` — separate
  hard-lock that also disables the read-only TOFU bootstrap. Default:
  unset, i.e. introspection is allowed. Only set this in air-gapped
  or attestation-only environments where *no* new trust anchor may be
  learned at runtime.

Call sites choose the correct gate based on what they intend to do:

- Read-only chain / leaf fetches use
  :func:`create_introspection_context`.
- Request-carrying transports or explicit ``verify_tls=False`` paths
  use :func:`create_insecure_context` /
  :func:`configure_unpinned_context`.
"""

from __future__ import annotations

import os
import ssl
import sys
import threading

from yggdrasim_common.process_debug import is_global_debug_enabled

__all__ = [
    "INSECURE_TLS_ENV",
    "REQUIRE_PINNED_TLS_ENV",
    "REQUIRE_PINNED_INTROSPECTION_TLS_ENV",
    "insecure_tls_allowed",
    "introspection_tls_allowed",
    "create_insecure_context",
    "configure_unpinned_context",
    "create_introspection_context",
]


INSECURE_TLS_ENV = "YGGDRASIM_SCP11_ALLOW_INSECURE_TLS"
REQUIRE_PINNED_TLS_ENV = "YGGDRASIM_SCP11_REQUIRE_PINNED_TLS"
REQUIRE_PINNED_INTROSPECTION_TLS_ENV = "YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION"

_BANNER_LOCK = threading.Lock()
_BANNER_SEEN: set[str] = set()
_INTROSPECTION_NOTE_LOCK = threading.Lock()
_INTROSPECTION_NOTE_SEEN: set[str] = set()


def _env_flag(name: str) -> bool:
    value = os.environ.get(name, "").strip().lower()
    return value in ("1", "true", "yes", "on")


def insecure_tls_allowed() -> bool:
    return _env_flag(INSECURE_TLS_ENV)


def introspection_tls_allowed() -> bool:
    """Return True unless the operator has explicitly hard-locked TOFU."""
    return _env_flag(REQUIRE_PINNED_INTROSPECTION_TLS_ENV) is False


def _pinning_required() -> bool:
    return _env_flag(REQUIRE_PINNED_TLS_ENV)


def _emit_banner(caller: str) -> None:
    label = str(caller or "<unknown>")
    with _BANNER_LOCK:
        if label in _BANNER_SEEN:
            return
        _BANNER_SEEN.add(label)
    sys.stderr.write(
        f"[SCP11] WARNING: TLS verification disabled for {label} "
        f"(opt-in via {INSECURE_TLS_ENV}=1). Never point this at a "
        "production RSP server.\n"
    )


def _emit_introspection_note(caller: str) -> None:
    """
    The TOFU chain introspection note is informational and fires once
    per call site. Keep it behind the global debug flag so nominal
    operator runs stay quiet; debug sessions still see the trail plus
    the hard-lock instructions.
    """
    if is_global_debug_enabled() is False:
        return
    label = str(caller or "<unknown>")
    with _INTROSPECTION_NOTE_LOCK:
        if label in _INTROSPECTION_NOTE_SEEN:
            return
        _INTROSPECTION_NOTE_SEEN.add(label)
    sys.stderr.write(
        f"[SCP11] info: TOFU chain introspection via {label} "
        f"(hard-lock with {REQUIRE_PINNED_INTROSPECTION_TLS_ENV}=1).\n"
    )


def _refuse(caller: str) -> None:
    raise RuntimeError(
        "Refusing to create an unpinned TLS context for "
        f"{caller!r}. Set {INSECURE_TLS_ENV}=1 to opt in "
        "(dev / SGP.26 test vectors only) or leave "
        f"{REQUIRE_PINNED_TLS_ENV}=1 set to keep pinning mandatory."
    )


def _refuse_introspection(caller: str) -> None:
    raise RuntimeError(
        "Refusing TLS chain introspection for "
        f"{caller!r} because {REQUIRE_PINNED_INTROSPECTION_TLS_ENV}=1 "
        "is set. Pre-seed the trust anchor under SCP11/<tree>/certs or "
        "unset the variable to allow TOFU learning."
    )


def create_insecure_context(caller: str) -> ssl.SSLContext:
    """Return an unverified SSL context, refusing unless explicitly opted in.

    For request-carrying transports only. Use
    :func:`create_introspection_context` for read-only chain fetches.
    """
    if _pinning_required():
        _refuse(caller)
    if insecure_tls_allowed() is False:
        _refuse(caller)
    _emit_banner(caller)
    return ssl._create_unverified_context()


def configure_unpinned_context(context: ssl.SSLContext, caller: str) -> ssl.SSLContext:
    """Downgrade an existing context to unpinned, honouring the same gate."""
    if _pinning_required():
        _refuse(caller)
    if insecure_tls_allowed() is False:
        _refuse(caller)
    _emit_banner(caller)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def create_introspection_context(caller: str) -> ssl.SSLContext:
    """Return an unverified SSL context intended for TOFU chain reads only.

    Allowed by default so the client can auto-learn trust anchors for
    freshly-seen FQDNs (new eUICC, new eIM operator, rotated TLS leaf).
    Refused only when the operator explicitly sets
    ``YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION=1``.

    Callers must not send any request body on the returned context.
    They are expected to wrap the socket, read the presented chain via
    ``get_unverified_chain`` or ``getpeercert(binary_form=True)`` and
    close immediately. The chain is then verified against a local
    bundle (pre-seeded or persisted from a previous TOFU bootstrap)
    before any real request is sent.
    """
    if introspection_tls_allowed() is False:
        _refuse_introspection(caller)
    _emit_introspection_note(caller)
    context = ssl._create_unverified_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
