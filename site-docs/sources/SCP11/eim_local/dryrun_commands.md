# Local eIM Dry-Run Command Scripts

## Script 1: IPAd Snapshot + IPAe Auth

```
HELP
IPAD-DISCOVER
EIM-PACKAGE-LINT
IPAE-AUTHENTICATE EIM-FIRST-TEST
HANDOVER-STATUS
NOTIF-HYGIENE 0
Q
```

## Script 2: Manual Transaction Handover + Download

```
HELP
HANDOVER-SET 11223344556677889900AABBCCDDEEFF EIM-FIRST-TEST
HANDOVER-STATUS
# Runtime will auto-handover BIP route to SM-DP+ during IPAE-DOWNLOAD.
IPAE-DOWNLOAD Workspace/LocalEIM/profile/test_profile.txt EIM-FIRST-TEST
NOTIF-HYGIENE 0
Q
```

## Script 3: eIM Certificate Provisioning Trial

```
HELP
EIM-PACKAGE Workspace/LocalEIM/eim_packages/default_eim_package.json
EIM-PACKAGE-LINT
ADD-INITIAL-EIM isdr "/path/to/local_eim_signing_cert.pem"
ADD-EIM package "/path/to/local_eim_signing_cert.pem" Workspace/LocalEIM/eim_packages/fake_eim_add_eim_package.json
EIM-ACKNOWLEDGE
NOTIF-HYGIENE 0
Q
```
