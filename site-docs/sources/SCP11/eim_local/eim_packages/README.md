<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# eIM Package JSON Templates

This directory stores JSON package objects used by the eIM local shell.

## Default file

- `default_eim_package.json`
- Template library: `templates/`
- Runtime hotfolder queue: `hotfolder/`

## Canonical seeded fake eIM artifacts

- `fake_eim_add_eim_package.json`
- `fake_eim_peer_addition_info.json`
- Legacy compatibility package: `first_test_add_eim_other_eim.json`

Use `fake_eim_add_eim_package.json` when another eIM or local harness needs a
fully populated `AddEim` package for the seeded YggdraSIM fake eIM.

Use `fake_eim_peer_addition_info.json` when the operator needs the complete
identity, endpoint, counter, and certificate inventory needed to carry that
fake eIM into another workflow or environment.

Simulator distinction:

- these package fixtures describe the Local eIM side and peer-provisioning data
- the simulated card's own default BF55 identity still comes from
  `Workspace/SIMCARD/eim_identity.json` unless a stronger card-side override is applied

## Core fields

- `package_type`
- `package_version`
- `spec_target`
- `sgp32` (spec-shaped object model)
- `runtime` (bridge hints for current shell implementation)
- `matching_id`
- `transaction_id_hex`
- `command_tag_hex`
- `include_cert_tag` (bool)
- `include_endpoint_tag` (bool)
- `include_matching_id_tag` (bool)
- `cert_der_path` (certificate file path; PEM and DER are both accepted by the runtime)
- `profile_path`
- `notification_policy`
- `bip_endpoints` (`eim`, `smdpp`)
- `additional_tlvs` (`include`, `tag_hex`, `value_hex`)
- `optional_tags` (`include`, `tag_hex`, `value_hex`)

## Multi-package simulation

- `EIM-PACKAGE-ISSUE <path>` executes one package based on `package_type`.
- `EIM-PACKAGE-ISSUE-ALL [dir]` executes all `.json` package files in a directory.
- `HOTFOLDER-LIST [dir]` previews effective queue order and order source.
- `HOTFOLDER-FETCH [dir]` executes the effective queue in resolved order.

Effective queue note:

- the effective queue is the merged set of package fixtures plus any `.json`
  files present in the hotfolder directory
- ordering follows `runtime.queue_id`, top-level `queue_id`,
  `runtime.transaction_id_hex`, numeric filename prefix, then lexical fallback
