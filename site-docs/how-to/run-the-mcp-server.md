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

Give an AI assistant the YggdraSIM tool surface, so it can do the work an
operator does rather than hand hex back and forth: decode an APDU or an
ASN.1 structure, resolve a status word or spec section, lint a SAIP package
or an eIM package, diff two session recordings, drive a card, and run batch
commands in the operator shells.

26 tools, 4 reference resources, and 3 canned workflows. Eight operator
shells are reachable through `shell_run`, covering 360 classified verbs --
every entry point in the project that has a batch mode.

The server speaks the Model Context Protocol over stdio and works with any
MCP client (Claude Code, Claude Desktop, and other MCP-capable tools).

What it deliberately does not do is decide it is allowed to act. Every
capability that changes something sits behind an opt-in an operator sets on
the server entry, described under [Access model](#access-model).

## Access model

The intent is that an agent can do what an operator can do, given the same
information -- build a SAIP profile, install an applet, test an OTA
envelope. What it cannot do is decide on its own that it is allowed to.

The server starts **read-only**, and three independent switches widen it.
None implies another, and each is set on the server entry rather than per
call, so the choice is persistent and visible.

| Variable | Off (default) | On |
| --- | --- | --- |
| `YGGDRASIM_MCP_ACCESS` | reads only | `write` also permits anything that changes state |
| `YGGDRASIM_MCP_ALLOW_CARD` | nothing reaches hardware | tools and verbs may reach a physical card |
| `YGGDRASIM_MCP_ALLOW_SCRIPT_FILES` | `RUN` / `SCRIPT` refused | an unverified command file may be executed |

`YGGDRASIM_MCP_ACCESS` is a mode, not a flag: it reads `write` (also
`readwrite`, `read-write`, `rw`) and treats everything else, including
`1` and `yes`, as read-only. A truthy-looking value is not a request for
write access.

The two axes are orthogonal on purpose. Write access without card access
builds profiles and OTA envelopes on disk and never touches hardware. Card
access without write access reads a card and cannot change it.

## Card safety

Several tools reach a real card: `pcsc_transmit` locally,
`card_bridge_transmit` through a relay, and the `card_session_*` tools
through a connection they hold open. An MCP client is usually an agent
acting without step-by-step review, and a wrong APDU is not always
recoverable. PIN and PUK retry counters only decrement, an ADM key can
block permanently, and a terminated card does not come back.

### Card access is off by default

Nothing reaches a card unless `YGGDRASIM_MCP_ALLOW_CARD` is set. With it
unset the card tools refuse with an explanation, and the rest of the 26
work normally.

Note what enabling it actually says: `card_bridge_transmit` reaches
whatever relay URL it is given, so the flag covers the local reader **and**
every rig this host can reach.

### Changing a card needs write access as well

With card access on, APDUs are classified by instruction byte, and the two
classes that change the card need `YGGDRASIM_MCP_ACCESS=write`:

| Class | Examples | Needs |
| --- | --- | --- |
| read | SELECT, READ BINARY, READ RECORD, GET STATUS | `ALLOW_CARD` |
| write | UPDATE BINARY, UPDATE RECORD, INSTALL, STORE DATA | `ALLOW_CARD` **and** `ACCESS=write` |
| destructive | VERIFY, CHANGE PIN, RESET RETRY COUNTER, PUT KEY, DELETE, SET STATUS, DEACTIVATE FILE, STORE DATA carrying an eUICC memory reset | `ALLOW_CARD` **and** `ACCESS=write` |

An instruction the table does not recognise is classified as **write**, not
read: not having seen an instruction is not evidence that it is safe.

Call `apdu_risk` to classify a command without sending it; it works with
every gate shut, and reports the current access mode alongside the class.

### A confirmation prompt before anything irreversible

When a destructive APDU is permitted, the server asks the client to confirm
with a human first, naming the operation and the target. The distinction
between write and destructive survives here even though both need the same
opt-in: reflashing a file and terminating a card are not the same act.

This is defence in depth, never the only guard. Elicitation is an optional
MCP capability, and a client that is itself an agent may answer the prompt
without asking anyone. A client that does not support it at all is not an
error; the server falls back to the environment gates. Those gates are what
actually hold.

### Credentials are never requested

The server never asks for a PIN, PUK, ADM key, or any other secret. The MCP
SDK scopes in-band elicitation to non-sensitive data for good reason, and
there is a sharper problem here: an agent client may answer a prompt
itself, so a fabricated PIN would be submitted to the card and consume a
real retry counter.

Secrets go in **by path**, configured out of band by a human:

```json
{"apdu_url": "http://127.0.0.1:8642/apdu",
 "token_file": "~/.config/yggdrasim/card_bridge/8642.token"}
```

The server reads the file itself and enforces `0600` on it. The agent
handles a filename, never a value, so nothing secret enters a tool
argument or a transcript. Authenticated flows such as SCP03 follow the same
rule: stage the keys as files first, then reference them by path.

A handful of shell verbs take key material as a positional argument --
`DERIVE-OPC` is the clearest -- and those are gated at the write tier
rather than refused outright. Refusing would be theatre: if the caller
supplied the key, it is already in the transcript. Prefer the by-path form
where the shell offers one, and treat any batch that carries a secret
inline as a batch whose transcript is now sensitive.

### Tool annotations

Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`), so a client can tell the difference
between `status_word_lookup` and `pcsc_transmit` without reading this page
and can prompt accordingly. 19 of the 26 tools are marked read-only; the
seven that are not are `pcsc_transmit`, `card_bridge_transmit`,
`shell_run`, `card_backend_select`, and the three `card_session_*` tools.

### Session state

`pcsc_transmit` connects, transmits one APDU, and disconnects. No session
survives between calls, so it suits stateless probes and **cannot** carry a
secure-channel flow: the second APDU of an SCP03 exchange would arrive on a
card that has forgotten the first.

There are two ways to keep state. `card_session_open` holds a connection
locally and hands back a session id to transmit through. Or run a Card
Bridge and use `card_bridge_transmit`: the bridge holds the reader and
relays through it, which is also what reaches a remote rig. See
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

Fifteen of the twenty-six tools work from that install alone, nineteen
with `[card]`. That includes driving a card: the transport chain is
vendored, so `card_session_open`, `card_session_transmit`, and
`card_bridge_transmit` all work without the rest of YggdraSIM. `[card]`
adds the three that need a local PC/SC driver; the relay path needs no
driver at all, so a standalone install with no pyscard can still drive a
card through a Card Bridge or a Remote Lab rig.

Seven tools need the full install and report that they are unavailable,
naming what is missing rather than raising: `saip_lint` and `saip_diff`
need the SAIP stack; `bpp_segment`, `metadata_lint`, and `eim_package_lint`
need the SCP11 code; `runtime_status` and `shell_run` need the full
runtime. The simulated backend is also full-install only -- `SIMCARD` is a
whole subsystem, so selecting `sim` on a standalone reports that plainly
and points at the reader backend.

The distribution publishes a single `yggdrasim_mcp` package rather than
re-providing `Tools` or `SCP03`, so it can be installed alongside the full
`yggdrasim` without a file collision. The tree is generated on demand from
these sources and is never committed, so it cannot drift from the code it
is cut from.

Every degraded tool is still registered, so an agent discovers it and gets
a reason instead of a missing capability it cannot ask about.

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
| `saip_diff` | structurally diff two SAIP packages: added, removed, changed, moved |
| `metadata_lint` | lint an SGP.22 profile metadata document |
| `eim_package_lint` | validate an SGP.32 eIM package against the ES2+ schema |
| `plugin_status` | report which optional plugin-backed capabilities are available |
| `runtime_status` | report the runtime root, build flavor, and live service state |
| `shell_run` | run a batch of operator-shell commands; **some of these reach a real card** |
| `session_diff` | diff the APDU traces of two session recordings |

`saip_lint` accepts the same inputs as `Package > Open`: binary DER, ASCII
hex text, ASN.1 value notation, or transcode JSON. Excel workbooks are
refused, because they are not SAIP packages; see the note on spreadsheet
extensions in [Build and Packaging](../build-and-packaging.md).

`session_diff` takes two recordings written by the shell recorder; see
[Diff Two Session Recordings](diff-two-session-recordings.md).

`saip_diff` bounds its response at 200 entries and reports how many were
dropped; a whole-package diff can run to thousands of nodes.

Upstream pySim logs the construction of every file in a profile at DEBUG,
which is over a hundred kilobytes of stderr per package load. Those
loggers are raised to WARNING; set `YGGDRASIM_MCP_UPSTREAM_LOG_LEVEL=DEBUG`
when actually debugging a decode.

### Card

| Tool | Card access | Purpose |
| --- | --- | --- |
| `pcsc_list_readers` | no | enumerate local PC/SC readers |
| `pcsc_transmit` | **yes** | transmit a raw APDU to a local physical card (stateless) |
| `card_bridge_transmit` | **yes** | transmit through a Card Bridge or Remote Lab relay (keeps session state) |
| `card_backend_status` | no | report which transport the stack talks through, and what is open |
| `card_backend_select` | for `reader` | point the stack at a local reader or the simulator |
| `card_session_open` | for `reader` | open a session that survives across calls, and read its ATR |
| `card_session_transmit` | for `reader` | send one APDU through an open session |
| `card_session_close` | no | close one session, or all of them |

### Choosing the transport

Three paths reach a card: a local PC/SC reader, a relay, or the built-in
simulator. `card_backend_status` reports which one is configured, where
that setting came from, and every session this server holds. It reads with
every gate shut, and reports whether a relay token exists rather than its
value.

`card_backend_select` switches between `reader` and `sim`. Both need write
access, because the choice outlives the call; selecting `reader`
additionally needs card access, since it points the whole stack at
hardware. `persist` is off by default -- with it on, the choice is written
to the runtime settings file and every other YggdraSIM process picks it up.

Selecting `sim` is how an agent does card work with no reader present: the
simulator answers real APDUs, so a SELECT/READ chain or a profile
inspection runs end to end. The card gate does not apply to it, because
there is no hardware to protect. Write access still does, because the
simulator carries state.

### Sessions

`pcsc_transmit` connects and disconnects around each APDU, so a
secure-channel flow cannot work through it: the second APDU of an SCP03
exchange arrives on a card that has forgotten the first.

`card_session_open` holds one connection open and returns a session id and
the ATR. Every `card_session_transmit` on that id runs on the same channel,
so the selected file, the logical channel, and the secure channel all
survive between calls. Each APDU is still classified individually, so a
read-only server can drive a whole inspection sequence and refuse the one
command that would change something.

Sessions expire after 10 minutes idle and at most 4 are held at once. The
handle pins a reader and keeps the card powered, so an unbounded registry
would leak both.

`card_bridge_transmit` reaches whatever rig its URL points at, so it sits
behind the same opt-in as `pcsc_transmit`. Enabling card access is
therefore not only a statement about the reader on this machine; it is a
statement about every relay this host can reach. For a Remote Lab rig the
token file holds the session token, not the bridge's own token.

### Running shell commands

!!! danger "These shells reach a real card"

    With every opt-in set, verbs reachable through `shell_run` can install
    applets, write keys, send an OTA envelope, export a key bag, and
    disable or delete a profile. **None of that can be undone.** Use a
    throwaway test card, never one carrying live credentials.

    Nothing reaches a card, and nothing changes state, unless *you* set the
    environment variables below. They are off by default and stay off until
    an operator turns them on deliberately.

`shell_run` executes a non-interactive batch in an operator shell, so an
agent can drive a workflow rather than only inspect single files:

```text
shell="profile_package"     USE /abs/profile.der; INFO; TREE; LINT; EXIT
shell="scp80"               SET /abs/keys.json; BUILD; EXIT
shell="scp11_eim"           EIM-PACKAGE /abs/pkg.json; EIM-PACKAGE-LINT; EXIT
shell="suci_tool"           STATUS; GENERATE secp256r1; DUMP; EXIT
shell="scp03"               SELECT 3F00; READ; INFO; EXIT
shell="scp11_live"          GET-EID; GET-EUICC-INFO2; LIST; EXIT
shell="scp11_relay"         GET-EID; GET-EUICC-INFO2; LIST; EXIT
shell="scp11_local_access"  LIST; PROFILE; METADATA; EXIT
```

All eight operator shells are exposed, covering 360 classified verbs:

| Shell | Opens a reader at startup | Verbs | Purpose |
| --- | --- | --- | --- |
| `profile_package` | no | 53 | SAIP package inspection and authoring |
| `scp80` | no | 15 | OTA: build an envelope offline, or `SEND` it to a card |
| `scp11_eim` | no | 74 | SGP.32 local eIM: author, lint, and issue eIM packages |
| `suci_tool` | no | 11 | SUCI key generation and public-key export |
| `scp03` | **yes** | 80 | card admin: filesystem, registry, GlobalPlatform |
| `scp11_live` | **yes** | 50 | SGP.22/SGP.32 profile download and eUICC management |
| `scp11_relay` | **yes** | 41 | SGP.22 relay compatibility console (ES2+/ES9+) |
| `scp11_local_access` | **yes** | 36 | local eUICC profile management over ES10 |

`scp11_relay` is the older console kept for the compatibility namespace. It
covers much of the same ES10 surface as `scp11_live`, and a test asserts
the two never classify a shared verb differently.

`scp80` and `scp11_eim` are the two that split the axes apart. Building an
OTA envelope or authoring and linting an eIM package is offline work that
needs write access and no card. The verbs that put those artefacts on a
card -- `SEND`, `SENDRAW`, `OTA` in `scp80`, and the issue / ISDR / profile
verbs in `scp11_eim` -- each carry their own card check even though the
shell itself opened no reader.

Each shell's verb set is read from that shell's own command table, and a
test compares the two in both directions on every run. A verb the shell
registers but the gate does not classify is refused as unknown, so the
failure mode is a capability going missing rather than an unguarded one.

### The gates

**A shell that opens a reader at startup needs
`YGGDRASIM_MCP_ALLOW_CARD`**, checked before the process starts. SCP03
connects to a reader during startup, so even `HELP` would touch hardware;
refusing early means it never gets that far. Individual verbs that reach a
card from an otherwise offline shell are gated the same way.

**Verbs are allow-listed, not deny-listed.** SCP03 alone carries 80
classified verbs. Read verbs run at any access level; anything that changes
state needs `YGGDRASIM_MCP_ACCESS=write`. An unrecognised verb is refused
rather than assumed harmless, and a refusal anywhere blocks the whole batch
before the process starts.

**Classification follows the leading verb**, so a verb that dispatches its
own subcommands is classified by the most dangerous thing it can reach:
`TOKENS` sits at the write tier because `TOKENS SET` writes, even though a
bare `TOKENS` only lists. Use the dedicated read verb where one exists --
`LIST-TOKENS` rather than `TOKENS` -- to stay inside read-only access.

**Verbs whose payload is never classified need their own opt-in.** `RUN`
and `SCRIPT` take a file of commands; `RAW` passes its arguments straight
through to the underlying tool. In each case the gate cannot see what will
actually run, so every other rule stops applying. Set
`YGGDRASIM_MCP_ALLOW_SCRIPT_FILES` when you specifically want an agent to
run something you have not had classified -- write access alone does not
grant it.

**Interactive verbs are refused at every level.** A batch has no terminal,
so a verb that opens a menu or prompts for input would hang until the
timeout rather than fail. This covers more than the obvious TUI entry
points: SCP03's `PUT-KEY`, `SET-STATUS`, and `MANAGE-PIN` are wizards, and
`scp80`'s `ADMIN` hands the reader to the SCP03 shell's own REPL.

### Enabling it

Opt in on the MCP server entry, so the choice is persistent and visible
rather than made per call:

```json
{
  "mcpServers": {
    "yggdrasim": {
      "command": "yggdrasim-mcp",
      "env": {
        "YGGDRASIM_MCP_ACCESS": "write",
        "YGGDRASIM_MCP_ALLOW_CARD": "1"
      }
    }
  }
}
```

Drop `YGGDRASIM_MCP_ALLOW_CARD` for a server that authors profiles and OTA
payloads but cannot touch hardware -- that combination covers most of the
build-side work with none of the irreversible risk. Add
`YGGDRASIM_MCP_ALLOW_SCRIPT_FILES` only when you intend an agent to run
unverified command files.

### Two things to know

**Pass absolute paths.** A shell resolves a relative path against its own
profile and transcode directories, not the working directory, so a
relative argument can silently act on a different package. The tool flags
any relative path argument and reports when the shell logged a missing
path.

**State does not survive between calls**, since each batch is a fresh
process. Put a whole flow in one batch.

**Ambiguity resolves upward.** Where a verb's own help text left its risk
open -- a package-issuing verb whose JSON the gate never reads, a flow
whose steps the remote side chooses -- it sits at the destructive tier
rather than the write tier. Guessing downward for a card shell is how an
agent wipes one.

### Service state is read-only

`runtime_status` reports the runtime root, build flavor, and whether the
HIL bridge and Remote Lab have live state. It does not start or stop
anything. Stopping a rig mid-session is a different class of risk from a
bad APDU, and the value does not justify handing that to an agent.

Rig entries come back through the registry's redacted view: it reports
whether a token file exists, never its path or contents.

### What is not exposed

The card, profile, and eUICC surfaces are covered end to end. Of the
project's other entry points, these are reachable only from a terminal:

| Entry point | Why |
| --- | --- |
| `yggdrasim-gui`, `yggdrasim-web-server` | long-running services with their own UI |
| `yggdrasim-hil-bridge`, `yggdrasim-hil-supervisor` | rig services; lifecycle is an operator decision |
| `yggdrasim-lab-agent`, `yggdrasim-card-bridge` | daemons; the MCP is a client of these, not their manager |
| `yggdrasim-profile-autoload` | watches for card insertion, so it never returns |
| `yggdrasim-apdu-fuzzer`, `yggdrasim-eum-diag` | no batch mode, and the fuzzer's own allow-list gate is the right place for that decision |

Every entry point with a batch mode is exposed. The services are
deliberate: starting and stopping a rig is a different class of risk from
a bad APDU, and a watcher that never returns cannot answer a tool call.
The last row has no `--cmd`, so there is nothing to classify.

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

### Capabilities are gated on the plugin being there

An agent should not have to discover a missing capability by failing. Call
`plugin_status` to see what is available:

```json
{"extensions_active": true,
 "plugin_tools": ["workbook_to_saip", "operator_plmn_lookup"],
 "plugin_loading_enabled": true}
```

Built-in tools that depend on a plugin answer differently in each case
rather than emitting one fixed refusal. `saip_lint` on a workbook is the
worked example, because Excel-to-SAIP generation is not part of the
published core:

- **no plugin** -- reports `plugin_available: false` and how to install one
- **plugin loaded** -- reports `plugin_available: true` and names the tool
  to call

A provider can set a `workbook_tool` attribute naming its converter, and
that tool is listed first. Without it the core lists every tool the plugin
added, since it cannot know which one handles a workbook.

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
- The file tools read any path you give them. Point them at captures and
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
