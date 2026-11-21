#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
#
# Verify a Remote Lab rig is reachable over the VPN, from an operator machine.
#
# Read-only: resolves, pings, and makes GET calls. Never reserves a session and
# never touches the card. The access token is read from its file and is never
# printed. Separates "the network is fine" from "the agent is bound wrong",
# which are the two failures that look identical in the GUI.
#
#   scripts/remote_lab_verify_over_vpn.sh <agent-fqdn> [token-file] [control-port] [stream-port]
set -uo pipefail

FQDN="${1:-}"
TOKEN_FILE="${2:-}"
CONTROL_PORT="${3:-8700}"
STREAM_PORT="${4:-8801}"

if [ -z "$FQDN" ]; then
  echo "usage: $0 <agent-fqdn> [token-file] [control-port] [stream-port]" >&2
  exit 2
fi

pass=0
fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; fail=$((fail + 1)); }

echo "== 1. Name resolves =="
IP="$(getent hosts "$FQDN" | awk '{print $1; exit}')"
if [ -n "$IP" ]; then
  ok "$FQDN -> $IP"
else
  bad "$FQDN does not resolve (a VPN may publish it as a routing-only domain; use the FQDN)"
fi

echo "== 2. Route and reachability =="
if [ -n "$IP" ]; then
  ip route get "$IP" 2>/dev/null | head -1 | sed 's/^/  route: /'
  if ping -c 2 -W 2 "$IP" >/dev/null 2>&1; then
    ok "ICMP to $IP"
  else
    bad "no ICMP reply from $IP -- check the VPN is up and routing that subnet"
  fi
fi

echo "== 3. Agent control port =="
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
        "http://${FQDN}:${CONTROL_PORT}/healthz" 2>/dev/null)"
if [ "$code" = "200" ]; then
  ok "/healthz -> 200"
else
  bad "/healthz -> ${code:-no answer} -- agent still loopback-bound? see remote_lab_open_agent_to_vpn.py"
fi

echo "== 4. Authenticated rig listing =="
if [ -z "$TOKEN_FILE" ]; then
  echo "  SKIP  no token file given"
elif [ ! -r "$TOKEN_FILE" ]; then
  bad "token file unreadable: $TOKEN_FILE"
else
  TOKEN="$(tr -d '[:space:]' < "$TOKEN_FILE")"
  body="$(curl -s --max-time 8 -H "Authorization: Bearer ${TOKEN}" \
          "http://${FQDN}:${CONTROL_PORT}/api/v1/rigs" 2>/dev/null)"
  if echo "$body" | grep -q '"id"'; then
    ok "rigs listed"
    echo "$body" | grep -oE '"(id|status|atr)"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/^/    /'
  else
    bad "no rig list (auth or agent problem): ${body:0:120}"
  fi
fi

echo "== 5. Stream port =="
if timeout 5 bash -c "echo > /dev/tcp/${FQDN}/${STREAM_PORT}" 2>/dev/null; then
  ok "stream port ${STREAM_PORT} accepts connections"
else
  bad "stream port ${STREAM_PORT} refused -- stream_proxy.bind_host still loopback?"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
