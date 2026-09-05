---
title: Write a Profile Policy Pack
tags:
  - how-to
  - saip
  - validation
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Write a Profile Policy Pack

## Goal

Make `VALIDATE` enforce your own profile rules instead of only the
3GPP/ETSI baseline, without patching `SCP03/logic/profile_validator.py`.

Most operators carry house rules on top of the standard: a file that is
optional in the spec but mandatory in your product, a fixed SFI you always
allocate, a size you always provision. A policy pack encodes those as data.

## Get a starting pack

The default pack is generated from the live expectation tables rather than
kept as a checked-in file, so it can never drift from the validator:

```bash
python -m SCP03.logic.profile_validator > Workspace/house-rules.yaml
```

That writes every built-in expectation in pack form. Edit it down to the
groups you actually want to change.

## Pack shape

```yaml
version: 1
groups:
  mf:
    - path: MF
      expected_type: DF
      expected_structure: Tree
      require_security: false
    - path: EF_ICCID
      expected_type: EF
      expected_structure: Transparent
      size: 10
  usim:
    - path: ADF_USIM/EF_IMSI
      expected_type: EF
      expected_structure: Transparent
      size: 9
      sfi: '07'
      require_security: false
```

Groups are `mf`, `usim`, `usim_gsm_access`, `usim_5gs`, `isim`, and
`isim_optional`.

**A group replaces its built-in table outright.** It does not merge entry by
entry. A group you leave out keeps the baseline untouched. The alternative,
merging, makes it impossible to tell by reading a pack which checks are
actually in force, which is the wrong trade for a validation tool.

### Expectation fields

| Field | Meaning |
| --- | --- |
| `path` | required; the file path, e.g. `ADF_USIM/EF_IMSI` |
| `expected_type` | required; `EF` or `DF` |
| `expected_structure` | required; `Transparent`, `Linear Fixed`, `Cyclic`, `Tree` |
| `size` | expected transparent-file size in bytes |
| `record_length` / `record_count` | expected record geometry |
| `sfi` | expected short file identifier, as hex text |
| `required` | whether absence is a failure (default `true`) |
| `require_security` | whether missing security attributes are a failure (default `true`) |
| `require_lcs` | whether a missing life-cycle status is a failure (default `true`) |
| `service_any` | only check when any of these UST service numbers is available |
| `content_pattern` | expected fixed content, as hex text |
| `pattern_scope` | `file` or `record` |
| `content_mismatch_severity` | `WARN` (default) or `FAIL` |

An unknown field is an error, not a silently ignored key. A typo like
`sizee: 10` would otherwise quietly disable a check.

## Use it

From the SCP03 shell:

```text
VALIDATE ALL POLICY=Workspace/house-rules.yaml
```

It composes with the existing metadata argument:

```text
VALIDATE USIM ProfileDump.yaml POLICY=Workspace/house-rules.yaml
```

The validation header prints which groups a pack overrode, so nobody has to
guess whether a finding came from the baseline or from your rules:

```text
=== PROFILE VALIDATION ===
[*] Scope: ALL
[*] Policy pack overrides: mf, usim
```

Pack paths resolve inside the workspace root, the same containment rule the
metadata argument uses.

## From Python

```python
from SCP03.logic.profile_validator import ProfileValidator, load_policy_pack

policy = load_policy_pack("Workspace/house-rules.yaml")
findings = ProfileValidator(fs_controller, policy=policy).run(scope="ALL")
```

## Validation

Check the pack parses before relying on it:

```bash
python -c "
from SCP03.logic.profile_validator import load_policy_pack
pack = load_policy_pack('Workspace/house-rules.yaml')
for group, entries in sorted(pack.items()):
    print(f'{group}: {len(entries)} expectation(s)')
"
```

A malformed pack raises `PolicyPackError` naming the offending entry, so
you are never left guessing which one is wrong:

```text
groups.usim[0].expected_structure is required
groups.usim[3] has unknown field(s): sizee. Known fields: ...
```

Then confirm it actually changes the outcome: run `VALIDATE` with and
without `POLICY=` against the same profile and compare the findings. A pack
that produces identical output is either redundant or not being loaded.

## Related pages

- [Inspect and Transcode SAIP](inspect-and-transcode-saip.md)
- [SCP03 Command Reference](../shell-guides/scp03-command-reference.md)
- [Profile Package](../subsystems/profile-package.md)
