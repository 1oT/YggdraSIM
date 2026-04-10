# Profile Lifecycle CLI Cheatsheet

This cheatsheet collects the highest-signal non-interactive commands for
profile download, enable, disable, delete, discovery, polling, and audit
workflows across the `SCP11` operator surfaces.

Use this together with:

- `CLI_AND_PIPING_GUIDE.md` for the generic `--cmd` / `--stdin` conventions
- `SCP11/README.md` for module selection
- `SCP11/local_access/README.md` and `SCP11/eim_local/GUIDE.md` for the local
  card and Local eIM operator models

## 1. Batch rules

- `--cmd` uses one semicolon-separated shell string.
- `--stdin` uses newline-separated shell commands.
- Finish scripted sessions with `EXIT`.
- Use `tee` when you want both terminal output and a saved artifact.
- Quote paths that contain spaces.

Examples:

```bash
python -m SCP11.local_access --cmd "DISCOVER; STATUS; EXIT"
```

```bash
python -m SCP11.eim_local --stdin <<'EOF'
STATUS
PATHS
EXIT
EOF
```

## 2. Relay shells: `SCP11.live` and `SCP11.test`

Use the relay shells when the workflow should model `LPAd`, `IPAd`, or
relay-style `IPAe`.

### 2.1 Snapshot and profile list

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; LIST; EXIT"
python -m SCP11.test --cmd "DISCOVER; STATUS; LIST; EXIT"
```

### 2.2 `LPAd` download from activation code

```bash
python -m SCP11.live --cmd "DOWNLOAD-PROFILE LPA:1$SMDP.EXAMPLE$TOKEN; STATUS; EXIT"
```

### 2.3 Enable, disable, and delete by ICCID or AID

```bash
python -m SCP11.live --cmd "ENABLE-PROFILE 8904903200000000000F; EXIT"
python -m SCP11.live --cmd "DISABLE-PROFILE A0000005591010FFFFFFFF8900000100; EXIT"
python -m SCP11.live --cmd "DELETE-PROFILE 8904903200000000000F; EXIT"
```

### 2.4 Relay polling

`POLL` and alias `EIM-POLL` are provided by the optional `polling` plugin.

```bash
python -m SCP11.live --cmd "POLL; EXIT"
python -m SCP11.test --cmd "POLL 3 30 --debug; EXIT"
```

### 2.5 Save relay output to a log

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; LIST; EXIT" | tee reports/scp11_live_snapshot.log
```

## 3. Local card shell: `SCP11.local_access`

Use the local shell when the workflow is direct `ISD-R` work rather than
relay emulation.

### 3.1 Discovery and certificate state

```bash
python -m SCP11.local_access --cmd "DISCOVER; STATUS; CERTS --json; EXIT"
```

### 3.2 Direct local profile load

```bash
python -m SCP11.local_access --stdin <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json
LOAD-PROFILE
EXIT
EOF
```

### 3.3 Enable, disable, and delete by ICCID, AID, or alias

```bash
python -m SCP11.local_access --cmd "ENABLE-PROFILE ISDP1; EXIT"
python -m SCP11.local_access --cmd "DISABLE-PROFILE 8904903200000000000F; EXIT"
python -m SCP11.local_access --cmd "DELETE-PROFILE ISDP1; EXIT"
```

Aliases also work:

```bash
python -m SCP11.local_access --cmd "ENABLE ISDP1; DISABLE ISDP1; DELETE ISDP1; EXIT"
```

### 3.4 Metadata lint and send

```bash
python -m SCP11.local_access --cmd "METADATA-LINT default_profile_metadata.json --yaml; EXIT"
python -m SCP11.local_access --cmd "STORE-METADATA; UPDATE-METADATA; EXIT"
```

### 3.5 Capture a replayable session

```bash
python -m SCP11.local_access --stdin <<'EOF'
RECORD START reports/local_smdpp_profile_load.yaml
DISCOVER
LOAD-PROFILE
RECORD STOP
EXIT
EOF
```

## 4. Local eIM shell: `SCP11.eim_local`

Use Local eIM when the workflow is package-driven, queue-driven, or handover
driven.

### 4.1 Local eIM snapshot and path sanity

```bash
python -m SCP11.eim_local --cmd "STATUS; PATHS; LIST; DISCOVER; EXIT"
```

### 4.2 Direct local profile load plus profile-state control

```bash
python -m SCP11.eim_local --stdin <<'EOF'
PROFILE Workspace/LocalEIM/profile/test_profile.txt
METADATA Workspace/LocalEIM/profile/metadata/default_profile_metadata.json
LOAD-PROFILE
ENABLE-PROFILE ISDP1
DISABLE-PROFILE ISDP1
DELETE-PROFILE ISDP1
EXIT
EOF
```

### 4.3 Localized `IPAd`

```bash
python -m SCP11.eim_local --cmd "IPAD-DISCOVER; IPAD-LIVE EIM-FIRST-TEST --debug; EXIT"
python -m SCP11.eim_local --cmd "IPAD-DISCOVER; IPAD-TEST EIM-FIRST-TEST; EXIT"
```

### 4.4 Localized `IPAe` handover

```bash
python -m SCP11.eim_local --stdin <<'EOF'
IPAE-AUTHENTICATE EIM-TEST-001
HANDOVER-STATUS
IPAE-DOWNLOAD Workspace/LocalEIM/profile/test_profile.txt EIM-TEST-001
EXIT
EOF
```

### 4.5 Optional plugin-backed localized watchdog polling

```bash
python -m SCP11.eim_local --cmd "IPAE-LIVE 3 15 -t 20s -s 5 --debug; EXIT"
python -m SCP11.eim_local --cmd "IPAE-TEST; EXIT"
```

### 4.6 Hotfolder and campaign queue work

```bash
python -m SCP11.eim_local --cmd "HOTFOLDER-LIST --json; EXIT"
python -m SCP11.eim_local --cmd "HOTFOLDER-FETCH --json; EXIT"
python -m SCP11.eim_local --cmd "POLL-CAMPAIGN --until-empty --max-cycles 50 --json; EXIT"
python -m SCP11.eim_local --cmd "POLL-EXPORT --until-empty --max-cycles 50 reports/eim_campaign.json; EXIT"
python -m SCP11.eim_local --cmd "POLL-AGGREGATE reports --json; EXIT"
```

### 4.7 Response log, counters, and notification hygiene

```bash
python -m SCP11.eim_local --cmd "RESP-LOG 50 --json; COUNTERS; NOTIF-HYGIENE 0; EXIT"
python -m SCP11.eim_local --cmd "RESP-LOG-FILTER MID-1 50 --yaml; EXIT"
python -m SCP11.eim_local --cmd "COUNTER 2.25.311782205282738360923618091971140414400 set 1; EXIT"
```

### 4.8 Save a Local eIM run to a log

```bash
python -m SCP11.eim_local --cmd "STATUS; PATHS; HOTFOLDER-LIST --json; EXIT" | tee reports/eim_local_overview.log
```

## 5. SAIP support commands for profile files

Use `Tools.ProfilePackage` before card work when the profile package itself is
the question.

### 5.1 Inspect, lint, and dump a profile package

```bash
python -m Tools.ProfilePackage --cmd "USE reference_test_profile.txt; INFO; TREE; LINT; EXIT"
python -m Tools.ProfilePackage --cmd "USE reference_test_profile.txt; DUMP ALL DECODED > reports/profile_dump.yaml; EXIT"
```

### 5.2 Interactive transcode UI

```bash
python -m Tools.ProfilePackage --cmd "USE reference_test_profile.txt; INSPECT; EXIT"
```

The transcode UI persists:

- `*.transcode.json`
- `*.transcode.der`
- `*.transcode.txt` as plain uppercase hex

## 6. Ready-to-paste patterns

### 6.1 Relay snapshot with log capture

```bash
python -m SCP11.live --stdin <<'EOF' | tee reports/live_relay_snapshot.log
DISCOVER
STATUS
LIST
EXIT
EOF
```

### 6.2 Local one-shot profile load with metadata

```bash
python -m SCP11.local_access --stdin <<'EOF' | tee reports/local_profile_load.log
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json
LOAD-PROFILE
STATUS
EXIT
EOF
```

### 6.3 Local eIM queue campaign

```bash
python -m SCP11.eim_local --stdin <<'EOF' | tee reports/eim_campaign.log
STATUS
PATHS
HOTFOLDER-LIST --json
POLL-CAMPAIGN --until-empty --max-cycles 25 --json
RESP-LOG 20
EXIT
EOF
```

## 7. Quick module choice

- Use `SCP11.live` or `SCP11.test` when the workflow is relay-first.
- Use `SCP11.local_access` when the workflow is direct `ISD-R` provisioning.
- Use `SCP11.eim_local` when the workflow is package-driven, queue-driven, or
  handover-driven.
- Use `Tools.ProfilePackage` when the profile file itself needs lint, decode, or
  transcode work before card operations.
