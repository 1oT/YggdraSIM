# Operator Surfaces

## Surface selection

| Surface | Use when | Representative capabilities | Main entry point |
| --- | --- | --- | --- |
| `main/main.py` | you want a unified launcher and guide entry point | module dispatch, docs, about, license, automation entry points | `python main/main.py` |
| `SCP03/` | the task is card administration, retrieval, GP auth, or filesystem work | secure-channel auth, app and package enumeration, ETSI and 3GPP file access, report and export flows | `python -m SCP03` |
| `SCP80/` | the task is OTA build, wrap, preview, send, or decode | OTA packet construction, direct hex handling, scripts, ICCID-bound state reuse | `python -m SCP80` |
| `SCP11/live/` | the workflow is relay-first and should match live defaults | `DOWNLOAD-PROFILE`, `DISCOVER`, `DOWNLOAD`, optional plugin-backed `POLL` | `python -m SCP11.live` |
| `SCP11/test/` | the workflow is relay-first but needs lab-only shaping or test defaults | live-shaped relay surface with test certificates and request-variant controls | `python -m SCP11.test` |
| `SCP11/local_access/` | the task is direct local `ISD-R` bring-up or one-shot profile load | local SCP11 auth, metadata upload, profile enable, disable, and delete | `python -m SCP11.local_access` |
| `SCP11/eim_local/` | the task is on the eIM side rather than the relay side | `ADD-EIM`, package queues, localized polling, handover, response logs | `python -m SCP11.eim_local` |
| `Tools/ProfilePackage/` | the task is SAIP package inspection or transcode work | inspect, lint, transcode, encode, split, extract | `python -m Tools.ProfilePackage` |
| `Tools/SuciTool/` | the task is SUCI key handling | key selection, key generation, public-key export | `python -m Tools.SuciTool` |
| `Tools/HilBridge/` | a live card must be bridged to a modem through SIMtrace2 | HIL bridge, supervisor lifecycle, GSMTAP mirroring, APDU side-channel access, AT+CSIM/CRSM transcoder | `python -m Tools.HilBridge.supervisor` |
| `Tools/ApduFuzz/` | the task is opt-in, allow-listed eUICC APDU mutation fuzzing | mutation-based APDU fuzzer with hard-gated allow list | `python -m Tools.ApduFuzz` |
| `Tools/EumDiag/` | the task is EUM / SM-DP+ traffic diagnostics or session-key injection | session-key staging plus Wireshark / tshark Lua dissector | `python -m Tools.EumDiag` |
| `SIMCARD/` | the task needs an in-process simulated UICC / eUICC instead of a physical reader | ETSI / GP / SCP03 / SCP80 / Toolkit / 5G AKA / AKMA / SUCI / `GET IDENTITY` | `--card-backend sim` on any launcher |
| `yggdrasim_common/gui_server/` | a desktop or web-served GUI Command Center is wanted | typed action registry, APDU recorder, FastAPI / pywebview surfaces | `python main/main.py --gui` or `--web-server` |

## Common automation patterns

Most shell-oriented modules expose one or more of these non-interactive forms:

- `--cmd "COMMAND; COMMAND; EXIT"` for semicolon-separated one-shot runs
- `--stdin` for here-doc or piped command batches
- file-driven script execution where the subsystem already defines it
- report and export modes for shells such as `SCP03`

Examples:

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; EXIT"
python -m SCP11.local_access --stdin <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
LOAD-PROFILE
EXIT
EOF
python -m SCP80 --cmd "show; history; exit"
```

## Practical rules

- Use `SCP03` for GlobalPlatform and filesystem work, not for relay provisioning.
- Use `SCP11/live` or `SCP11/test` when the operator model is relay-first.
- Use `SCP11/local_access` when the operator model is direct local `ISD-R`.
- Use `SCP11/eim_local` when the operator model is eIM-side package or handover work.
- Use `Tools/ProfilePackage` before card work when the package needs inspection, linting, or transcode.
- Use `Tools/HilBridge` when a physical card must stay in a reader while also serving a modem.
- Use `Tools/ApduFuzz` only on lab-only eUICCs after explicitly enabling the allow-list gate.
- Use `Tools/EumDiag` when an EUM / SM-DP+ capture must be replayed or decoded with operator-side keys.
- Use `--card-backend sim` to swap in the in-process simulator without touching shell command surfaces.
- Use `--gui` or `--web-server` to bring up the Universal GUI Command Center on top of any backend.

## Related source guides

- `guides/CAPABILITIES.md`
- `guides/CLI_AND_PIPING_GUIDE.md`
- `guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
- `SCP11/README.md`
