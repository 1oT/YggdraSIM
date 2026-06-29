<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# eIM Package Template Library

This directory holds the canonical package templates for the eIM local shell
bubble. There is now one canonical template filename per `package_type`.
Historical references and old naming variants were removed from this directory
to keep the operator surface clean.

## Usage

1. Copy a template to `../` or point commands at it directly.
2. Set `include` booleans to `true` for the fields and tags you want emitted.
3. Fill any `value`, `value_hex`, or path fields you enable.
4. Run `EIM-PACKAGE-LINT <path>` before issuing.

Card-side note:

- these templates are for Local eIM package construction and relay-side/localized execution
- they do not change the simulated card's seeded BF55 identity by themselves
- use `Workspace/SIMCARD/eim_identity.json` or `Workspace/SIMCARD/isdr_config.json` when the card-side default also needs to move

Templates use `sgp32` or `sgp22` sections plus `runtime` hints for the current
eIM local shell and localized bridge.

## Canonical Templates

- `template_add_initial_eim.json`
- `template_add_eim.json`
- `template_get_eim_package.json`
- `template_profile_download_trigger_request.json`
- `template_provide_eim_package_result.json`
- `template_bound_profile_package.json`
- `template_euicc_memory_reset.json`
- `template_eim_acknowledgements.json`
- `template_eim_package_request.json`
- `template_eim_package_result.json`
- `template_euicc_package_request_eim_configuration_data.json`
- `template_euicc_package_request_ecos.json`
- `template_euicc_package_request_psmos.json`
- `template_euicc_package_result.json`
- `template_profile_download_trigger_result.json`

## Template Notes

- `template_add_initial_eim.json` aligns to ES10b `AddInitialEimRequest` (`BF57`).
- `template_add_eim.json` aligns to eCO `AddEim`.
- `template_get_eim_package.json` aligns to ESipa `GetEimPackageRequest` (`BF4F`).
- `template_provide_eim_package_result.json` aligns to ESipa `ProvideEimPackageResult` (`BF50`).
- `template_profile_download_trigger_request.json` models the indirect SM-DP+ handover request path.
- `template_bound_profile_package.json` models the direct BF36 profile relay path.
- `template_euicc_memory_reset.json` defaults to selective `reset_eim_config_data` only.
- `template_eim_acknowledgements.json` closes pending eIM operations.
- `template_eim_package_request.json` is the top-level all-branch request CHOICE map.
- `template_eim_package_result.json` is the top-level all-branch result CHOICE map.
- `template_euicc_package_request_*.json` and `template_*_result.json` cover the individual branch families for request/result composition work.

## Execution Scope

- Directly executable now via `EIM-PACKAGE-ISSUE`:
  - `add_initial_eim`
  - `add_eim`
  - `get_eim_package`
  - `profile_download_trigger_request`
  - `provide_eim_package_result`
  - `bound_profile_package`
  - `euicc_memory_reset`
- Schema-first templates:
  - `eim_package_request`
  - request/result branch families intended for linting, composition, and mock-registration mode unless `runtime.allow_model_only` is enabled
