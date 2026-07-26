---
title: Diff Two Session Recordings
tags:
  - how-to
  - apdu
  - diagnostics
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Diff Two Session Recordings

## Goal

Answer the question a card lab asks constantly: the same script ran against
two cards, or against one card before and after a change, so where did they
stop agreeing?

`yggdrasim-session-diff` compares the APDU traces of two shell session
recordings and reports only what differs: status words, response bodies,
and exchanges present on one side only.

## Record both sessions

The session recorder lives in the SCP11 Local Access and SCP11 eIM Local
shells. Run the same command sequence against each card:

```text
RECORD START Workspace/card-a.yaml
... run the sequence ...
RECORD STOP
```

Then repeat against the second card into `Workspace/card-b.yaml`.

`RECORD [STATUS|START|STOP|CANCEL]` is the session recorder in those
shells. Do not confuse it with the SCP03 shell's `RECORD <n|ALL|start-end>`,
which is READ RECORD against a card file and writes no recording.

The recorder writes `.yaml`, `.yml`, or `.json`; the diff reads all three.

## Compare them

```bash
yggdrasim-session-diff Workspace/card-a.yaml Workspace/card-b.yaml
```

```text
left : Workspace/card-a.yaml  (146 exchanges)
right: Workspace/card-b.yaml  (147 exchanges)

3 difference(s): 1 status, 1 response, 0 only-left, 1 only-right

L41/R41  status differs  00A4000402FFFF
        left : 9000
        right: 6A82
L58/R58  response differs  00B0000010
        left : 98620000000000000001
        right: 98620000000000000002
L-/R92   only in right  00C0000010
```

Exit status is `0` when the traces match, `1` when they diverge, and `2`
when a file could not be read, so a shell loop can branch on it:

```bash
if ! yggdrasim-session-diff baseline.yaml candidate.yaml > /dev/null; then
  echo "card behaviour changed"
fi
```

`--json` emits the same result as a machine-readable object.

## How exchanges are aligned

Alignment is on the command APDU, not on position. A single extra exchange
on one side (a retry, an added GET RESPONSE) would otherwise shift every
following index and make the rest of the run look different when only one
thing changed. With APDU-keyed alignment that insertion shows up as one
`only in right` entry and the rest still lines up.

The consequence worth knowing: if the two runs issue genuinely different
command sequences, you get paired `only in left` / `only in right` entries
rather than a "changed" entry, because there is no matching command to
compare a response against.

## Response payloads are truncated

APDU responses can carry PINs, keys, and operator secrets. Text output
clips payloads to 32 hex characters and tells you the true length:

```text
        left : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA... (128 hex chars)
```

Pass `--full` to print them untruncated. Do that only when you know what
is in the trace and where the output is going.

## From an AI assistant

The same comparison is available as the `session_diff` MCP tool; see
[Run the MCP Server](run-the-mcp-server.md).

## From Python

```python
from yggdrasim_common.session_diff import diff_recordings

result = diff_recordings("card-a.yaml", "card-b.yaml")
if not result.identical:
    first = result.first_divergence
    print(first.kind, first.left_index, first.apdu_hex)
```

## Validation

Diff a recording against itself. It must report `APDU traces are identical`
and exit `0`:

```bash
yggdrasim-session-diff Workspace/card-a.yaml Workspace/card-a.yaml
```

If that reports differences, the recordings carry per-run state (timestamps
inside a response, a counter) rather than the tool being wrong.

## Related pages

- [Run the MCP Server](run-the-mcp-server.md)
- [Diagnostics Toolbox](diagnostics-toolbox.md)
- [Replay a HIL pcap offline](replay-hil-pcap-offline.md)
