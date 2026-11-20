<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Local eIM Dry-Run Command Scripts


```
HELP
IPAD-DISCOVER
EIM-PACKAGE-LINT
HANDOVER-STATUS
NOTIF-HYGIENE 0
Q
```

## Script 2: Manual Transaction Handover + Download

```
HELP
HANDOVER-SET 11223344556677889900AABBCCDDEEFF EIM-FIRST-TEST
HANDOVER-STATUS
NOTIF-HYGIENE 0
Q
```

## Script 3: eIM Certificate Provisioning Trial

```
HELP
EIM-PACKAGE Workspace/LocalEIM/eim_packages/default_eim_package.json
EIM-PACKAGE-LINT
ADD-INITIAL-EIM package "/path/to/local_eim_signing_cert.pem" Workspace/LocalEIM/eim_packages/templates/template_add_initial_eim.json
GET-EIM-CONFIG
EIM-ACKNOWLEDGE
NOTIF-HYGIENE 0
Q
```
