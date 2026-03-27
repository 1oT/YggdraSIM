# First Test Setup

This setup seeds one concrete first-test identity and package set for the local eIM module.

## Identity

- eIM ID: `2.25.311782205282738360923618091971140414400`
- eIM ID type: `OID`
- eIM FQDN: `yggdrasim.eim.test.1ot.com`
- eIM endpoint: `https://yggdrasim.eim.test.1ot.com/gsma/rsp2/asn1`
- SM-DP+ endpoint: `https://yggdrasim.smdpp.test.1ot.com/gsma/rsp2/es9plus`
- SM-DP+ address: `yggdrasim.smdpp.test.1ot.com`
- CI PKID: `F54172BDF98A95D65CBEB88A38A1C11D800A85C3`

The first-test signing and TLS-trust material used by the canonical peer package
is seeded from the local reference chain:

- signing cert: `SCP11/eim_local/certs/eim/CERT_S_EIMsign_YGGDRASIM_NIST.pem`
- signing key: `SCP11/eim_local/certs/eim/SK_S_EIMsign_YGGDRASIM_NIST.pem`
- TLS cert: `SCP11/eim_local/certs/eim/CERT_S_EIM_TLS_YGGDRASIM_NIST.pem`
- TLS private key: `SCP11/eim_local/certs/eim/SK_S_EIM_TLS_YGGDRASIM_NIST.pem`
- CI root: `SCP11/eim_local/certs/eim/CA.EIM.Root.cert.pem`

Default identity note:

- `eim_identity.json` still pins the Local eIM default signing certificate to
  `CERT_S_EIMsign_YGGDRASIM_ACCEPTED.der`
- command examples that pass `CERT_S_EIMsign_YGGDRASIM_NIST.pem` are explicitly
  overriding that identity default for the first-test workflow

## Canonical Peer Provisioning Artifacts

Use these files when another eIM or harness needs to provision this fake eIM:

- executable AddEim package:
  - `SCP11/eim_local/eim_packages/fake_eim_add_eim_package.json`
- machine-readable peer dossier:
  - `SCP11/eim_local/eim_packages/fake_eim_peer_addition_info.json`

Legacy compatibility package still exists:

- `SCP11/eim_local/eim_packages/first_test_add_eim_other_eim.json`

The document is already pinned to:

- counter value `0`
- association token request `FF` by using `association_token.value = -1`
- `eimRetrieveHttps = true`
- `indirectProfileDownload = true`
- explicit signing and trusted TLS certificate paths that exist in the seeded tree

## Retrieval And Acknowledgement Queue

Fixed fixture packages remain in the permanent poll queue:

- `SCP11/eim_local/eim_packages/fixtures/eim_to_esim/010_profile_download_trigger_request_first_download.json`
- `SCP11/eim_local/eim_packages/fixtures/esim_to_eim/020_provide_eim_package_result_first_download.json`
- `SCP11/eim_local/eim_packages/fixtures/eim_to_esim/030_eim_acknowledgements_first_download.json`

The hotfolder now also contains one explicit first-test package:

- `SCP11/eim_local/eim_packages/hotfolder/110_first_test_profile_download_trigger_request.json`

Queue order is deterministic:

1. fixed trigger fixture (`queue_id = 10`)
2. fixed BF50 result fixture (`queue_id = 20`)
3. fixed acknowledgement fixture (`queue_id = 30`)
4. hotfolder trigger (`queue_id = 110`)

## Default Runtime Seeds

- `SCP11/eim_local/eim_identity.json` now points to the seeded first-test identity and certificate set.
- `SCP11/eim_local/eim_runtime_state.json` seeds counter `1` for `2.25.311782205282738360923618091971140414400`.
- `SCP11/eim_local/eim_packages/default_eim_package.json` is aligned to the fixed first-test transaction.

## Suggested Shell Sequence

```shell
python -m SCP11.eim_local
STATUS
ADD-INITIAL-EIM package "SCP11/eim_local/certs/eim/CERT_S_EIMsign_YGGDRASIM_NIST.pem" SCP11/eim_local/eim_packages/templates/template_add_initial_eim.json
GET-EIM-CONFIG
ADD-EIM package "SCP11/eim_local/certs/eim/CERT_S_EIMsign_YGGDRASIM_NIST.pem" SCP11/eim_local/eim_packages/fake_eim_add_eim_package.json
HOTFOLDER-LIST --json
POLL-CAMPAIGN --until-empty --max-cycles 10 --json
RESP-LOG 20
```

## Operational Note

The shipped OID is a UUID-derived dummy under `2.25`, not a copied private-enterprise branch. `yggdrasim.eim.test.1ot.com` and `yggdrasim.smdpp.test.1ot.com` can still be carried through the package runtime fields, while the module continues to use its local intercept path for execution.
