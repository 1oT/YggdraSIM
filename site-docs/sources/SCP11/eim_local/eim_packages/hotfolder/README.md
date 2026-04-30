# eIM Package Hotfolder

This directory contributes the dynamic runtime entries for `HOTFOLDER-FETCH`,
`POLL-CAMPAIGN`, and related queue operations. Use `HOTFOLDER-LIST` to preview
resolved queue order before issuing.

## Ordering rules

Files are issued in ascending numeric order using this precedence:

1. `runtime.queue_id` (integer, recommended)
2. top-level `queue_id` (integer)
3. `runtime.transaction_id_hex` (hex interpreted as integer)
4. leading numeric filename prefix (for example `001_...json`)
5. fallback lexical filename order

When the effective queue has no remaining JSON files, runtime poll response is:

- `eimPackageError = noEimPackageAvailable(1)`
- encoded as `BF4F03020101` (SGP.32 GetEimPackageResponse error branch)

## Recommended structure

- Use one JSON package per file.
- Set `runtime.queue_id` as `1, 2, 3, ...` for deterministic sequence.
- Optionally set `runtime.transaction_id_hex` manually to align with your test choreography.

## Example file names

- `001_add_initial_eim.json`
- `002_add_eim.json`
- `010_get_eim_package.json`
- `020_profile_download_trigger_request.json`
- `030_profile_download_trigger_result.json`
