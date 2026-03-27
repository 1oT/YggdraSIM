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
IPAE-DOWNLOAD SCP11/eim_local/profile/test_profile.txt EIM-FIRST-TEST
NOTIF-HYGIENE 0
Q
```

## Script 3: eIM Certificate Provisioning Trial

```
HELP
EIM-PACKAGE SCP11/eim_local/eim_packages/default_eim_package.json
EIM-PACKAGE-LINT
ADD-INITIAL-EIM isdr "SCP11/eim_local/certs/eim/CERT_S_EIMsign_YGGDRASIM_NIST.pem"
ADD-EIM package "SCP11/eim_local/certs/eim/CERT_S_EIMsign_YGGDRASIM_NIST.pem" SCP11/eim_local/eim_packages/fake_eim_add_eim_package.json
EIM-ACKNOWLEDGE
NOTIF-HYGIENE 0
Q
```
