# Card Bridge

Standalone PC/SC relay daemon. Publishes a locally-attached smart-card
reader over a loopback HTTP endpoint; intended for SSH-tunnelled access
from another machine running the YggdraSIM toolchain.

```
+------------------+        ssh -L 8642:127.0.0.1:8642        +------------------+
| Raspberry Pi /   |  <==== encrypted SSH tunnel  ====>       |   PC with reader |
| YggdraSIM tool   |                                          |   Card Bridge    |
| RelayCardConn    |  ----- HTTP, loopback only ------>       |   pyscard        |
+------------------+                                          +------------------+
```

## Quick start

**1. On the PC (where the card lives):**

```bash
python -m Tools.CardBridge \
    --port 8642 \
    --reader-name "ACR38U"
```

The bridge prints a banner with the URL, the on-disk token file, and
a short fingerprint. The full token never appears in the banner or in
logs — operators retrieve it via `cat ~/.config/yggdrasim/card_bridge/8642.token`.

**2. On the Raspberry Pi (where the tool runs):**

```bash
ssh -fN -L 8642:127.0.0.1:8642 hampus@pc-host

YGGDRASIM_CARD_RELAY_URL=http://127.0.0.1:8642/apdu \
YGGDRASIM_CARD_RELAY_TOKEN_FILE=$(ssh hampus@pc-host \
    realpath ~/.config/yggdrasim/card_bridge/8642.token) \
yggdrasim ...
```

Or, equivalently, copy the token over once via `scp` and reference the
local copy in subsequent invocations.

## Security posture

| Property | Provided by |
|---|---|
| Stream confidentiality | OpenSSH transport (ChaCha20-Poly1305 / AES-GCM). |
| Stream integrity | OpenSSH MAC + SSH sequence numbers. |
| Peer authentication | OpenSSH public-key auth (`~/.ssh/authorized_keys`). |
| Authorization | Bearer token written 0600 by the bridge, presented in `Authorization: Bearer …` by the client. |
| Network exposure | Bridge binds to `127.0.0.1` by default. Non-loopback bind without a token is refused. |
| Replay protection | SSH sequence numbers per session. |
| DoS resistance | Per-peer auth-failure rate limit + lockout. |
| Audit | Header-only structured log on the bridge; SSH session log on `sshd`. |

## CLI flags

| Flag | Default | Notes |
|---|---|---|
| `--host` | `127.0.0.1` | Anything else requires a non-empty token. |
| `--port` | `8642` | TCP listen port. |
| `--reader-index` | `0` | Position within the local PC/SC reader list. |
| `--reader-name` | empty | Substring match; overrides `--reader-index`. |
| `--token-file` | `${XDG_CONFIG_HOME:-~/.config}/yggdrasim/card_bridge/<port>.token` | If the file exists, the bridge reads it; if missing, generates a fresh token and writes it 0600. |
| `--no-token` | off | Run unauthenticated. Refused on non-loopback bind. |
| `--audit` | off | Emit a header-only audit record per APDU. |
| `--audit-full-apdu` | off | Also log full APDU and response hex. **Captures PIN material — only enable for forensic work on test cards.** |
| `--audit-logger-name` | `yggdrasim.card_bridge.audit` | Name of the Python logger that receives audit records. |

## Wire protocol

The Card Bridge speaks the same protocol as the existing HilBridge
APDU relay; all routes mount under the bind URL.

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| GET | `/ping` | open | — | `pong\n` |
| GET | `/status` | bearer | — | `{"reader", "atr", "authRequired", "tokenFingerprint", ...}` |
| POST | `/apdu` | bearer | `{"apdu": "<hex>", "sessionId": "<optional>"}` | `{"data": "<hex>", "sw1": "<hex>", "sw2": "<hex>"}` |
| POST | `/modem/refresh` | bearer | `{"mode": "...", "sessionId": "..."}` | implementation-defined; `503` from the Card Bridge daemon (no modem to refresh). |

When the bridge is in unauthenticated loopback mode, all routes accept
requests without a header. As soon as a token is configured, every
route except `/ping` requires `Authorization: Bearer <token>`.

## See also

- `guides/CARD_BRIDGE_GUIDE.md` — operator workflow, including
  `~/.ssh/config` snippets and troubleshooting.
- `yggdrasim_common/card_bridge_auth.py` — shared token utilities.
- `Tools/HilBridge/apdu_relay.py` — relay HTTP handler (also
  consumed by the in-tree HIL bridge).
