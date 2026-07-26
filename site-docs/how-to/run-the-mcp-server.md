---
title: Run the MCP Server
tags:
  - how-to
  - mcp
  - apdu
  - saip
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Run the MCP Server

## Goal

Give an AI assistant the YggdraSIM decode and lint surfaces as callable
tools, so it can parse an APDU, resolve a status word, look up a BER-TLV
tag or spec section, scan a file for telecom identifiers, and lint a SAIP
profile package without a human pasting hex back and forth.

The server speaks the Model Context Protocol over stdio and works with any
MCP client (Claude Code, Claude Desktop, and other MCP-capable tools).

## Card safety

Two tools drive a real card: `pcsc_transmit` locally and
`card_bridge_transmit` through a relay. An MCP client is usually an agent
acting without step-by-step review, and a wrong APDU is not always
recoverable. PIN and PUK retry counters only decrement, an ADM key can
block permanently, and a terminated card does not come back.

There are three layers in front of that, in order.

### 1. Card access is off by default

Nothing reaches a card unless `YGGDRASIM_MCP_ALLOW_CARD` is set. With it
unset both card tools refuse with an explanation, and the other 14 tools
work normally.

Note what enabling it actually says: `card_bridge_transmit` reaches
whatever relay URL it is given, so the flag covers the local reader **and**
every rig this host can reach.

### 2. Irreversible instructions need a second opt-in

With card access on, APDUs are classified by instruction byte and the
irreversible ones still refuse:

| Class | Examples | Needs |
| --- | --- | --- |
| read | SELECT, READ BINARY, READ RECORD, GET STATUS | `ALLOW_CARD` |
| write | UPDATE BINARY, UPDATE RECORD, INSTALL, STORE DATA | `ALLOW_CARD` |
| destructive | VERIFY, CHANGE PIN, RESET RETRY COUNTER, PUT KEY, DELETE, SET STATUS, DEACTIVATE FILE, STORE DATA carrying an eUICC memory reset | `ALLOW_CARD` **and** `YGGDRASIM_MCP_ALLOW_DESTRUCTIVE` |

An instruction the table does not recognise is classified as **write**, not
read: not having seen an instruction is not evidence that it is safe.

Most useful agent work is reads, so the middle tier is the one to run in.
Call `apdu_risk` to classify a command without sending it; it works with
the gates shut.

### 3. A confirmation prompt before anything irreversible

When a destructive APDU is permitted, the server asks the client to confirm
with a human first, naming the operation and the target.

This is defence in depth, never the only guard. Elicitation is an optional
MCP capability, and a client that is itself an agent may answer the prompt
without asking anyone. A client that does not support it at all is not an
error; the server falls back to the environment gates. Those gates are what
actually hold.

### Credentials are never requested

The server never asks for a PIN, PUK, ADM key, or any other secret, and no
tool takes one as an argument. The MCP SDK scopes in-band elicitation to
non-sensitive data for good reason, and there is a sharper problem here: an
agent client may answer a prompt itself, so a fabricated PIN would be
submitted to the card and consume a real retry counter.

Secrets go in **by path**, configured out of band by a human:

```json
{"apdu_url": "http://127.0.0.1:8642/apdu",
 "token_file": "~/.config/yggdrasim/card_bridge/8642.token"}
```

The server reads the file itself and enforces `0600` on it. The agent
handles a filename, never a value, so nothing secret enters a tool
argument or a transcript. Authenticated flows such as SCP03 follow the same
rule: stage the keys as files first, then reference them by path.

### Tool annotations

Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`), so a client can tell the difference
between `status_word_lookup` and `pcsc_transmit` without reading this page
and can prompt accordingly. 14 of the 16 tools are marked read-only.

### Session state

`pcsc_transmit` connects, transmits one APDU, and disconnects. No session
survives between calls, so it suits stateless probes and **cannot** carry a
secure-channel flow: the second APDU of an SCP03 exchange would arrive on a
card that has forgotten the first.

For anything that needs session state, run a Card Bridge and use
`card_bridge_transmit`. The bridge holds one connection to the reader and
relays through it, so the channel survives across calls. See
[Remote APDU Streaming](remote-apdu-streaming.md).

Whatever the layers say: use a throwaway test card, not one carrying live
credentials.

## Install

```bash
python -m pip install -e '.[mcp]'
```

The `mcp` extra is opt-in: neither the base install nor `[full]` pulls it
in, so a normal runtime never carries the server.

### Standalone, without the rest of YggdraSIM

Most of the tools decode bytes and resolve identifiers, which needs no
card stack. `scripts/release/build_mcp_standalone.py` generates a separate
`yggdrasim-mcp` distribution carrying just those:

```bash
python scripts/release/build_mcp_standalone.py --wheel-out dist/
pip install dist/yggdrasim_mcp-*.whl          # decode, lookup, diff tools
pip install 'yggdrasim_mcp-*.whl[card]'       # adds the PC/SC tools
```

It declares only `mcp`, `pyyaml`, and `asn1crypto`, with `pyscard`
optional because it needs a compiler and the PCSC headers. No Git
dependencies, so a plain `pip` resolves it.

Twelve of the sixteen tools work from that install alone, thirteen with
`[card]`. `saip_lint` and `bpp_segment` report that they are unavailable,
because they need the pySim profile stack and the SCP11 session code
respectively.

The distribution publishes a single `yggdrasim_mcp` package rather than
re-providing `Tools` or `SCP03`, so it can be installed alongside the full
`yggdrasim` without a file collision. The tree is generated on demand from
these sources and is never committed, so it cannot drift from the code it
is cut from.

`saip_lint` additionally needs the SAIP stack, which is part of the base
install. If it is somehow unavailable the tool reports that rather than
raising.

## Register it with a client

For Claude Code:

```bash
claude mcp add yggdrasim -- yggdrasim-mcp
```

For a client that reads a JSON config, the equivalent entry is:

```json
{
  "mcpServers": {
    "yggdrasim": {
      "command": "yggdrasim-mcp"
    }
  }
}
```

To enable card access for a supervised session, add the environment
variable to that entry:

```json
{
  "mcpServers": {
    "yggdrasim": {
      "command": "yggdrasim-mcp",
      "env": { "YGGDRASIM_MCP_ALLOW_CARD": "1" }
    }
  }
}
```

From a source checkout without installing, `python -m Tools.YggdraMCP.server`
is equivalent.

## Tools

### Lookup

| Tool | Purpose |
| --- | --- |
| `status_word_lookup` | resolve SW1/SW2, including the `61xx`, `6Cxx`, and `63Cx` families |
| `ber_tlv_lookup` | name a single BER-TLV tag with its spec citation |
| `spec_section_lookup` | resolve a spec section identifier |
| `aide_registry_lookup` | resolve an application identifier |
| `validate_identifier` | check an ICCID, IMSI, EID, or similar against its rules |

### Decode

| Tool | Purpose |
| --- | --- |
| `apdu_parse` | split a command APDU into CLA/INS/P1/P2/Lc/data/Le |
| `asn1_decode` | recursively decode BER/DER TLV or a full APDU into a named tree |
| `sgp32_decode` | decode an SGP.32/SGP.22 response body: `euicc_info1`, `notifications`, `rat_rules`, `eim_configuration`, `get_certs` |
| `bpp_segment` | show how a Bound Profile Package splits into ES10b segments per Annex M |
| `apdu_risk` | classify an APDU as read, write, or irreversible without sending it |

`apdu_parse` and `ber_tlv_lookup` answer narrow questions (header fields,
one tag). `asn1_decode` parses a whole structure, resolving every nested
tag against the GSMA/3GPP index with its spec source, so a complete
`EuiccInfo2` comes back as structure rather than hex. It tries BER/DER
first and falls back to APDU interpretation, so a bare command APDU
decodes too.

### Files

| Tool | Purpose |
| --- | --- |
| `saip_lint` | lint a SAIP package and return the `YRL-*` findings |
| `session_diff` | diff the APDU traces of two session recordings |
| `scan_identifiers` | sweep a file for telecom identifiers |

`saip_lint` accepts the same inputs as `Package > Open`: binary DER, ASCII
hex text, ASN.1 value notation, or transcode JSON. Excel workbooks are
refused, because they are not SAIP packages; see the note on spreadsheet
extensions in [Build and Packaging](../build-and-packaging.md).

`session_diff` takes two recordings written by the shell recorder; see
[Diff Two Session Recordings](diff-two-session-recordings.md).

### Card

| Tool | Card access | Purpose |
| --- | --- | --- |
| `pcsc_list_readers` | no | enumerate local PC/SC readers |
| `pcsc_transmit` | **yes** | transmit a raw APDU to a local physical card (stateless) |
| `card_bridge_transmit` | **yes** | transmit through a Card Bridge or Remote Lab relay (keeps session state) |

`card_bridge_transmit` reaches whatever rig its URL points at, so it sits
behind the same opt-in as `pcsc_transmit`. Enabling card access is
therefore not only a statement about the reader on this machine; it is a
statement about every relay this host can reach. For a Remote Lab rig the
token file holds the session token, not the bridge's own token.

## Resources

Reference tables an agent can read whole instead of spending a tool call
per lookup:

| URI | Contents |
| --- | --- |
| `yggdrasim://reference/status-words` | every status word the server can name |
| `yggdrasim://reference/ber-tlv-tags` | BER-TLV tags with spec citations |
| `yggdrasim://reference/spec-sections` | the spec-section index |
| `yggdrasim://reference/test-identifier-ranges` | standards-reserved test ranges to use instead of real allocations |

## Prompts

Canned workflows that chain the tools in a sensible order:

| Prompt | Use when |
| --- | --- |
| `triage_failed_profile_download` | an SGP.22/SGP.32 download failed and you want the cause, not a guess |
| `explain_apdu_exchange` | you have one command/response pair and want it read back in full |
| `review_profile_package` | you want a SAIP package triaged into things actually worth fixing |

These are deliberately generic. Anything encoding operator specifics --
real PLMNs, house profile rules, rig inventory -- belongs in a private
plugin rather than the published server, the same split the vendor-quirk
configuration uses.

## Private extensions

A plugin under the runtime root can add its own tools, resources, and
prompts by registering the `mcp_extensions` capability:

```python
class OperatorMcpExtensions:
    def register(self, mcp) -> None:
        @mcp.prompt()
        def house_profile_review(file_path: str = "") -> str:
            return f"Review {file_path} against the house rules ..."


def register_plugins(manager) -> None:
    manager.register_capability("mcp_extensions", OperatorMcpExtensions())
```

Plugin loading is opt-in, because a plugin is executable Python from the
runtime root:

```bash
YGGDRASIM_ALLOW_PLUGINS=1 yggdrasim-mcp
```

`YGGDRASIM_DISALLOW_PLUGINS=1` hard-locks the loader and wins over the
opt-in.

The server starts either way. A plugin that is absent, unhealthy, or raises
is logged and skipped rather than taking the server down with it. A plugin
tool that drives a card must call `card_access_allowed()` itself; see
[Plugin Contract](../internals/plugin-contract.md).

## Validation

Confirm the server starts and the client sees it:

```bash
yggdrasim-mcp </dev/null
```

It exits immediately on a closed stdin, which is enough to prove the entry
point and the `mcp` extra resolve. If the extra is missing you get a
one-line install hint instead of a traceback.

Confirm the gates are where you expect. Ask the assistant to call
`apdu_risk` on `80E400000A` (a DELETE); it should report `destructive` and
`would_be_sent: false` without touching anything.

With the opt-in unset, ask it to transmit an APDU: it should come back with
`Card access is disabled`, naming the environment variable. With
`YGGDRASIM_MCP_ALLOW_CARD=1` but not the destructive flag, a SELECT should
go through while a VERIFY is refused as irreversible.

## Security rules

- Keep `YGGDRASIM_MCP_ALLOW_CARD` unset for unattended sessions. It gates
  both the local reader and every relay this host can reach.
- `scan_identifiers` reads any path you give it. Point it at captures and
  fixtures, not at a home directory.
- Tool output flows back to a model provider. Treat an APDU trace the same
  way you would treat it in a bug report: it can carry PINs and operator
  secrets.
- The server binds nothing. It speaks stdio to its parent process only,
  so there is no listening port to firewall.

## Related pages

- [Build and Packaging](../build-and-packaging.md)
- [Inspect and Transcode SAIP](inspect-and-transcode-saip.md)
- [Diagnostics Toolbox](diagnostics-toolbox.md)
