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

The first-test signing and TLS-trust material is no longer bundled in the
repository.

Provide local operator-owned material instead:

- signing cert: `/path/to/local_eim_signing_cert.pem`
- signing key: `/path/to/local_eim_signing_key.pem`
- TLS cert: `/path/to/local_eim_tls_cert.pem`
- TLS private key: `/path/to/local_eim_tls_key.pem`
- CI root: `/path/to/local_eim_ci_root_cert.pem`

Default identity note:

- `eim_identity.json` does not pin bundled Local eIM certificate material
- command examples should pass operator-provided paths explicitly, or the
  operator can populate the identity file locally
- the simulated card now uses its own default BF55 identity file under
  `Workspace/SIMCARD/eim_identity.json`

## Canonical Peer Provisioning Artifacts

Use these files when another eIM or harness needs to provision this fake eIM:

- executable AddEim package:
  - `Workspace/LocalEIM/eim_packages/fake_eim_add_eim_package.json`
- machine-readable peer dossier:
  - `Workspace/LocalEIM/eim_packages/fake_eim_peer_addition_info.json`

Legacy compatibility package still exists:

- `Workspace/LocalEIM/eim_packages/first_test_add_eim_other_eim.json`

The document is already pinned to:

- counter value `0`
- association token request `FF` by using `association_token.value = -1`
- `eimRetrieveHttps = true`
- `indirectProfileDownload = true`
- explicit signing and trusted TLS certificate placeholder paths that operators
  are expected to replace locally

## Retrieval And Acknowledgement Queue

Fixed fixture packages remain in the permanent poll queue:

- `Workspace/LocalEIM/eim_packages/fixtures/eim_to_esim/010_profile_download_trigger_request_first_download.json`
- `Workspace/LocalEIM/eim_packages/fixtures/esim_to_eim/020_provide_eim_package_result_first_download.json`
- `Workspace/LocalEIM/eim_packages/fixtures/eim_to_esim/030_eim_acknowledgements_first_download.json`

The hotfolder now also contains one explicit first-test package:

- `Workspace/LocalEIM/eim_packages/hotfolder/110_first_test_profile_download_trigger_request.json`

Queue order is deterministic:

1. fixed trigger fixture (`queue_id = 10`)
2. fixed BF50 result fixture (`queue_id = 20`)
3. fixed acknowledgement fixture (`queue_id = 30`)
4. hotfolder trigger (`queue_id = 110`)

## Default Runtime Seeds

- `Workspace/LocalEIM/eim_identity.json` now points to the seeded first-test identity without bundled certificate material.
- `Workspace/SIMCARD/eim_identity.json` seeds the simulator's default BF55 card-side identity separately from the Local eIM shell identity.
- copy matching values into `Workspace/SIMCARD/eim_identity.json`, use the wrapper `eIM identity` setting, or pass `--sim-eim-identity` when you want the simulated card to advertise a different local or real eIM.
- use `Workspace/SIMCARD/isdr_config.json` with `eim_entries` when the simulator needs more than one seeded card-side eIM row.
- `Workspace/LocalEIM/eim_runtime_state.json` seeds counter `1` for `2.25.311782205282738360923618091971140414400`.
- `Workspace/LocalEIM/eim_packages/default_eim_package.json` is aligned to the fixed first-test transaction and uses operator placeholder certificate paths.

## Suggested Shell Sequence

```shell
python -m SCP11.eim_local
STATUS
ADD-INITIAL-EIM package "/path/to/local_eim_signing_cert.pem" Workspace/LocalEIM/eim_packages/templates/template_add_initial_eim.json
GET-EIM-CONFIG
ADD-EIM package "/path/to/local_eim_signing_cert.pem" Workspace/LocalEIM/eim_packages/fake_eim_add_eim_package.json
HOTFOLDER-LIST --json
POLL-CAMPAIGN --until-empty --max-cycles 10 --json
RESP-LOG 20
```

## Operational Note

The shipped OID is a UUID-derived dummy under `2.25`, not a copied private-enterprise branch. `yggdrasim.eim.test.1ot.com` and `yggdrasim.smdpp.test.1ot.com` can still be carried through the package runtime fields, while the module continues to use its local intercept path for execution.
