<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Local profile metadata

This folder contains JSON files used to build metadata ASN.1 payloads at runtime.

Supported metadata command encoders:

- `StoreMetadataRequest` (`BF25`)
- `UpdateMetadataRequest` (`BF2A`)
- custom re-tagged `StoreMetadataRequest` payloads (for vendor/AOSP wrappers such as `BF76`)

## Canonical metadata file

Use `default_profile_metadata.json` as the single metadata file for:

- `STORE-METADATA` (`BF25`)
- `UPDATE-METADATA` (`BF2A`)
- custom metadata sends from the `custom` section.

## StoreMetadataRequest ASN.1 (required fields and sizes)

- **Tag**: `[37]` / `BF25`
- **iccid** (Iccid): required
- **serviceProviderName** `[17]` UTF8String **SIZE(0..32)** — Tag `91`
- **profileName** `[18]` UTF8String **SIZE(0..64)** — Short Description per SGP.21; Tag `92`
- **iconType** `[19]` IconType OPTIONAL — Tag `93` (JPG or PNG)
- **icon** `[20]` OCTET STRING **SIZE(0..1024)** OPTIONAL — only if iconType present; Tag `94`
- **profileClass** `[21]` ProfileClass DEFAULT operational — Tag `95`
- **notificationConfigurationInfo** `[22]` SEQUENCE OF NotificationConfigurationInformation OPTIONAL
- **profileOwner** `[23]` OperatorId OPTIONAL — Tag `B7`
- **profilePolicyRules** `[25]` PprIds OPTIONAL — Tag `99`
- Further optional fields (e.g. `[34]` serviceSpecificDataStoredInEuicc, `[35]` serviceSpecificDataNotStoredInEuicc, RPM/LPR/Enterprise, etc.) are defined in the spec but may not be present in the local encoder.

**NotificationEvent** (BIT STRING) used in `notificationConfigurationInfo`:

- bit 0: notificationInstall
- bit 1: notificationLocalEnable
- bit 2: notificationLocalDisable
- bit 3: notificationLocalDelete
- bit 4: notificationRpmEnable
- bit 5: notificationRpmDisable
- bit 6: notificationRpmDelete
- bit 7: loadRpmPackageResult

**NotificationConfigurationInformation** ::= SEQUENCE { profileManagementOperation NotificationEvent, notificationAddress UTF8String }

The codec enforces: `serviceProviderName` ≤ 32 characters, `profileName` ≤ 64 characters, `icon` ≤ 1024 octets.

## Resolution rules

- Keep exactly one `.json` file in this folder (`default_profile_metadata.json`) for deterministic default behavior.
- `README.md` is ignored by the resolver.

Main JSON to ASN.1 projection:

- `profile.iccid` -> `StoreMetadataRequest.iccid`
- `operator.name` -> `StoreMetadataRequest.serviceProviderName`
- `profile.name` -> `StoreMetadataRequest.profileName`
- `profile.profile_class` -> `StoreMetadataRequest.profileClass`
- `profile.icon.type` -> `StoreMetadataRequest.iconType`
- `profile.icon.data_hex` -> `StoreMetadataRequest.icon`
- `operator.mcc` + `operator.mnc` -> `StoreMetadataRequest.profileOwner.mccMnc`
- `operator.gid1` -> `StoreMetadataRequest.profileOwner.gid1`
- `operator.gid2` -> `StoreMetadataRequest.profileOwner.gid2`
- `notification_events` (install, enable, disable, delete, rpm_enable, rpm_disable, rpm_delete, load_rpm_package_result) -> `StoreMetadataRequest.notificationConfigurationInfo[].profileManagementOperation` (NotificationEvent bit order 0..7)
- `notification_events.address` -> `StoreMetadataRequest.notificationConfigurationInfo[].notificationAddress`
- `policy_rules.update_control_forbidden|disable_not_allowed|delete_not_allowed` -> `StoreMetadataRequest.profilePolicyRules`

Spreadsheet fields kept in JSON for later loading logic, but not projected into
`StoreMetadataRequest` yet:

- `profile.id`
- `profile.profile_type`
- `profile.state`
- `profile.is_enabled`
- `profile.profile_package`
- `operator.oid`
- `subscription_address.*`
- `download.*`
- `confirmation_code.*`
- `platform.*`
- `service_specific_data.*`
- `android.*`

Supported enum values:

- `profile.profile_class`: `TEST`, `TESTING`, `PROV`, `PROVISIONING`, `OPER`, `OPERATIONAL`
- `profile.icon.type`: `NONE`, `JPEG`, `JPG`, `PNG`

## UpdateMetadataRequest projection

`UpdateMetadataRequest` uses optional fields only. The local encoder maps:

- `operator.name` -> `UpdateMetadataRequest.serviceProviderName` (`91`)
- `profile.name` or `profile.profile_type` -> `UpdateMetadataRequest.profileName` (`92`)
- `profile.icon.type` -> `UpdateMetadataRequest.iconType` (`93`)
- `profile.icon.data_hex` -> `UpdateMetadataRequest.icon` (`94`)
- `policy_rules.*` -> `UpdateMetadataRequest.profilePolicyRules` (`99`)

At least one mapped field must be present for `UPDATE-METADATA`.

## `custom` section (tag-granular payload control)

`custom` is a nested object with groups and tag rows:

- `custom.<group>.<TAG_HEX>.include` (`true`/`false`)
- `custom.<group>.<TAG_HEX>.value_hex` (hex TLV value bytes, no spaces)

Behavior:

- `STORE-METADATA-CUSTOM <tagHex>` uses the enabled `custom` row for that tag when present.
- `STORE-METADATA-CUSTOM-ALL` sends every enabled row recursively across all groups.
- If a custom row for `<tagHex>` is not enabled, single-tag command falls back to re-tagged `BF25`.

## Loading and running from shell

Set active metadata file:

- `METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json`

Use active metadata file:

- `STORE-METADATA`
- `UPDATE-METADATA`
- `STORE-METADATA-CUSTOM BF76`
- `STORE-METADATA-CUSTOM-ALL`
- `METADATA-LINT`

Or pass path directly:

- `STORE-METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json`
- `UPDATE-METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json`
- `STORE-METADATA-CUSTOM BF76 Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json`
- `STORE-METADATA-CUSTOM-ALL Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json`

Related operator docs:

- `../../README.md`
- `../../../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
