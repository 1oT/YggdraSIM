# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""In-card TLS-1.2 client used by the SGP.32 IPA-poll eIM leg.

This module wraps Python's ``ssl.MemoryBIO`` so the simulator can drive
a TLS-1.2 ECDHE-ECDSA-AES128-GCM-SHA256 handshake one BIP SEND/RECEIVE
DATA at a time. The real eUICC carries the entire TLS state machine in
the card and emits TLS records as proactive SEND DATA payloads; the
modem becomes a transparent byte pipe to the eIM. The simulator now
mirrors that contract: the bytes a real card would put on the bearer
match what we put on the bearer.

The class is intentionally keyed off two memory BIOs so the toolkit's
proactive-command FSM can pump bytes in and out reactively:

* ``feed_inbound`` writes the channel data the modem returned on
  RECEIVE DATA into the inbound BIO.
* ``drain_outbound`` reads whatever the TLS engine produced (handshake
  flights, ChangeCipherSpec, encrypted application data) so the
  toolkit can ship it as the next SEND DATA payload.
* ``drive_handshake`` advances the handshake whenever new inbound
  bytes are available; it returns ``True`` once the handshake has
  fully completed.
* ``encrypt_application_data`` / ``decrypt_application_data`` operate
  after the handshake completes.

Cipher suite is pinned to ``ECDHE-ECDSA-AES128-GCM-SHA256``
(IANA 0xC02B) and the minimum/maximum TLS version is fixed at 1.2 so
the handshake matches what real reference IPA implementations emit.
The trust anchor comes from the eIM identity's
``trusted_tls_cert_path``; when that file is missing or unreadable the
client falls back to ``ssl.CERT_NONE`` so the simulator continues to
work in lab setups that have not provisioned a CA bundle yet.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final


PINNED_CIPHER_SUITE: Final[str] = "ECDHE-ECDSA-AES128-GCM-SHA256"
PINNED_TLS_VERSION: Final[str] = "TLSv1_2"


@dataclass(slots=True)
class CardTlsClientConfig:
    """Static knobs the toolkit hands to ``create_card_tls_client``.

    ``server_hostname`` is the eIM FQDN; it travels as ServerName in
    the ClientHello SNI extension and is the value the certificate
    chain validator matches against. ``ca_certificate_paths`` lists
    PEM/DER files that compose the trust anchor; when empty the client
    skips chain validation (useful during early lab bring-up).
    ``insecure_skip_verify`` is an explicit override that disables
    chain validation even when CA paths are supplied -- intended for
    operators who want to capture the raw TLS bytes without provisioning
    a trust anchor.
    """

    server_hostname: str
    ca_certificate_paths: list[str] = field(default_factory=list)
    ca_certificate_der: bytes = b""
    insecure_skip_verify: bool = False
    pinned_cipher: str = PINNED_CIPHER_SUITE


@dataclass(slots=True)
class CardTlsClientState:
    """Runtime container the toolkit owns across SEND/RECEIVE DATA TRs.

    The two ``MemoryBIO`` instances are the wire-level boundary: the
    toolkit feeds bytes from the modem into ``incoming`` and drains
    handshake/application bytes from ``outgoing``. ``ssl_object``
    advances the OpenSSL state machine; once it stops raising
    ``SSLWantReadError`` the handshake has completed.
    """

    config: CardTlsClientConfig
    incoming: ssl.MemoryBIO = field(default_factory=ssl.MemoryBIO)
    outgoing: ssl.MemoryBIO = field(default_factory=ssl.MemoryBIO)
    ssl_object: ssl.SSLObject | None = None
    handshake_complete: bool = False
    handshake_error: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0


def create_card_tls_client(config: CardTlsClientConfig) -> CardTlsClientState:
    """Build a memory-BIO TLS engine pinned to TLS-1.2 + ECDHE-ECDSA.

    The client context enforces:

    * ``minimum_version == maximum_version == TLSv1.2`` so the
      ClientHello advertises legacy_version=0x0303 with no TLS-1.3
      fallback.
    * ``set_ciphers(PINNED_CIPHER_SUITE)`` so OpenSSL emits a single
      cipher suite (0xC02B) in the ClientHello, matching the reference
      card byte for byte.
    * ``check_hostname=True`` + ``CERT_REQUIRED`` when CA material is
      supplied, otherwise ``CERT_NONE`` so unconfigured workspaces
      still produce a syntactically valid handshake (operators can then
      configure ``trusted_tls_cert_path`` and re-run).
    """

    state = CardTlsClientState(config=config)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError):
        # Older / patched Python builds may not expose TLSVersion;
        # the OPTIONS-style fallback still pins TLS-1.2 by disabling
        # everything else.
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.options |= getattr(ssl, "OP_NO_TLSv1_3", 0)
    try:
        context.set_ciphers(config.pinned_cipher)
    except ssl.SSLError:
        context.set_ciphers("ECDHE+AESGCM")
    _install_trust_anchor(context, config, state)
    state.ssl_object = context.wrap_bio(
        state.incoming,
        state.outgoing,
        server_hostname=str(config.server_hostname or ""),
    )
    return state


def _install_trust_anchor(
    context: ssl.SSLContext,
    config: CardTlsClientConfig,
    state: CardTlsClientState,
) -> None:
    if config.insecure_skip_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return
    loaded_any = False
    for raw_path in config.ca_certificate_paths or []:
        cert_path = Path(str(raw_path or "").strip())
        if str(cert_path) == "" or cert_path.is_file() is False:
            continue
        try:
            context.load_verify_locations(cafile=str(cert_path))
            loaded_any = True
        except (ssl.SSLError, OSError) as exc:
            state.handshake_error = (
                f"failed to load TLS trust anchor {cert_path}: {exc}"
            )
    der_blob = bytes(config.ca_certificate_der or b"")
    if len(der_blob) > 0:
        try:
            pem_blob = ssl.DER_cert_to_PEM_cert(der_blob)
            context.load_verify_locations(cadata=pem_blob)
            loaded_any = True
        except (ssl.SSLError, ValueError) as exc:
            state.handshake_error = (
                f"failed to install DER TLS trust anchor: {exc}"
            )
    if loaded_any:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        # No trust anchor configured: emit a syntactically valid
        # handshake but accept whatever certificate the eIM presents.
        # Operators can configure ``trusted_tls_cert_path`` to lock
        # the chain down once they have one.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE


def feed_inbound(state: CardTlsClientState, data: bytes) -> None:
    payload = bytes(data or b"")
    if len(payload) == 0:
        return
    state.incoming.write(payload)
    state.bytes_received += len(payload)


def drain_outbound(state: CardTlsClientState) -> bytes:
    chunk = state.outgoing.read()
    if len(chunk) > 0:
        state.bytes_sent += len(chunk)
    return bytes(chunk)


def drive_handshake(state: CardTlsClientState) -> bool:
    """Advance the TLS handshake using whatever inbound bytes are buffered.

    Returns ``True`` once the handshake has completed (and remains
    ``True`` on every subsequent call). Returns ``False`` while the
    engine is still waiting for more inbound bytes; the caller should
    drain ``outgoing`` (if non-empty), ship those bytes via SEND DATA,
    and then issue another RECEIVE DATA to refill ``incoming``.

    A non-``SSLWantReadError`` exception terminates the handshake;
    ``handshake_error`` captures the reason so the toolkit can surface
    it to operators / tests.
    """

    if state.ssl_object is None:
        state.handshake_error = "ssl_object missing"
        return False
    if state.handshake_complete:
        return True
    try:
        state.ssl_object.do_handshake()
    except ssl.SSLWantReadError:
        return False
    except ssl.SSLError as exc:
        state.handshake_error = f"ssl error: {exc}"
        return False
    except OSError as exc:
        state.handshake_error = f"os error: {exc}"
        return False
    state.handshake_complete = True
    return True


def encrypt_application_data(state: CardTlsClientState, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` and return the resulting TLS records.

    The caller is expected to have already completed the handshake;
    when called too early the function returns an empty buffer so the
    toolkit's queueing can stay defensive.
    """

    if state.ssl_object is None or state.handshake_complete is False:
        return b""
    payload = bytes(plaintext or b"")
    if len(payload) == 0:
        return b""
    state.ssl_object.write(payload)
    return drain_outbound(state)


def decrypt_application_data(state: CardTlsClientState, max_bytes: int = 16384) -> bytes:
    """Decrypt whatever application data has been buffered so far.

    Drains every plaintext fragment OpenSSL is willing to release in a
    single non-blocking read pass. ``max_bytes`` caps each individual
    read; the helper keeps reading until either OpenSSL signals
    ``SSLWantReadError`` (no more decrypted data available) or returns
    an empty buffer (clean shutdown).
    """

    if state.ssl_object is None or state.handshake_complete is False:
        return b""
    chunks: list[bytes] = []
    cap = max(1, int(max_bytes))
    for _ in range(64):
        try:
            chunk = state.ssl_object.read(cap)
        except ssl.SSLWantReadError:
            break
        except ssl.SSLZeroReturnError:
            break
        if len(chunk) == 0:
            break
        chunks.append(chunk)
    return b"".join(chunks)
