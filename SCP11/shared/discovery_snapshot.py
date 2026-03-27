from __future__ import annotations

from typing import Any

try:
    from SCP03.logic.euicc_info2 import build_euicc_info2_detail_lines
    from SCP03.logic.sgp32_decode import (
        decode_eim_configuration_entries,
        decode_euicc_info1_summary,
        decode_get_certs_response,
        decode_notifications_response,
        decode_rat_rules,
    )
except Exception:
    build_euicc_info2_detail_lines = None
    decode_eim_configuration_entries = None
    decode_euicc_info1_summary = None
    decode_get_certs_response = None
    decode_notifications_response = None
    decode_rat_rules = None


def _hex_preview(value: bytes, max_chars: int = 48) -> str:
    if len(value) == 0:
        return "-"
    encoded = value.hex().upper()
    if len(encoded) <= max_chars:
        return encoded
    return f"{encoded[:max_chars]}..."


def _short_text(value: str, max_len: int = 64) -> str:
    cleaned = str(value or "").strip()
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[:max_len] + "..."


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return bytes(value)
    if isinstance(value, bytearray):
        return bytes(value)
    return b""


def _print_profiles_table(entries: list[Any]) -> None:
    print("\n[+] GetProfilesInfo")
    if len(entries) == 0:
        print("    | (No profile metadata decoded)")
        return
    print("    | State     Class  ICCID                 Nickname                  AID")
    print("    | " + "-" * 94)
    for entry in entries:
        nickname = str(getattr(entry, "nickname", "")).strip()
        if len(nickname) == 0:
            nickname = str(getattr(entry, "profile_name", "")).strip()
        aid = _short_text(str(getattr(entry, "aid", "")).strip().upper(), 40)
        print(
            "    | "
            f"{str(getattr(entry, 'state', '')).strip():<9} "
            f"{str(getattr(entry, 'profile_class', '')).strip():<6} "
            f"{str(getattr(entry, 'iccid', '')).strip():<20} "
            f"{_short_text(nickname, 24):<24} "
            f"{aid}"
        )


def _print_configured_status_from_decoded(decoded: dict[str, Any], raw_data: bytes) -> None:
    print("\n[+] GetEuiccConfiguredData")
    default_smdp = str(decoded.get("default_smdp", "")).strip()
    root_smds_primary = str(decoded.get("root_smds_primary", "")).strip()
    root_smds_additional = decoded.get("root_smds_additional", [])
    allowed_ci_pkid = decoded.get("allowed_ci_pkid", [])
    print(f"    | Default SM-DP+       : {default_smdp or '-'}")
    print(f"    | Root SM-DS          : {root_smds_primary or '-'}")
    if isinstance(root_smds_additional, list) and len(root_smds_additional) > 0:
        print(
            "    | Additional SM-DS    : "
            + ", ".join(_short_text(str(value), 40) for value in root_smds_additional)
        )
    else:
        print("    | Additional SM-DS    : -")
    if isinstance(allowed_ci_pkid, list) and len(allowed_ci_pkid) > 0:
        print(
            "    | Allowed CI PKIDs    : "
            + ", ".join(_short_text(str(value).upper(), 40) for value in allowed_ci_pkid)
        )
    else:
        print("    | Allowed CI PKIDs    : -")
    if len(raw_data) > 0:
        print(f"    | Raw                 : {_hex_preview(raw_data, max_chars=120)}")


def _print_euicc_info1_compact(response: bytes) -> None:
    print("\n[+] GetEuiccInfo1")
    if len(response) == 0:
        print("    | (Empty)")
        return
    if decode_euicc_info1_summary is None:
        print(f"    | Raw                 : {_hex_preview(response, max_chars=120)}")
        return
    summary = decode_euicc_info1_summary(response)
    if len(summary) == 0:
        print(f"    | Raw                 : {_hex_preview(response, max_chars=120)}")
        return
    svn = str(summary.get("svn", "")).strip()
    if len(svn) > 0:
        print(f"    | SVN                 : {svn}")
    print(f"    | CI PK Verify Entries: {summary.get('ci_pk_verify_entries', 0)}")
    print(f"    | CI PK Sign Entries  : {summary.get('ci_pk_sign_entries', 0)}")


def _print_euicc_info2_compact(response: bytes) -> None:
    print("\n[+] GetEuiccInfo2")
    if len(response) == 0:
        print("    | (Empty)")
        return
    if build_euicc_info2_detail_lines is None:
        print(f"    | Raw                 : {_hex_preview(response, max_chars=120)}")
        return
    for indent_level, label, value in build_euicc_info2_detail_lines(response):
        prefix = "    | "
        if indent_level > 0:
            prefix = "    | " + ("  " * indent_level)
        print(f"{prefix}{label:<20}: {value}")


def _print_rat_compact(response: bytes) -> None:
    print("\n[+] GetRAT")
    if len(response) == 0:
        print("    | (Empty)")
        return
    if decode_rat_rules is None:
        print(f"    | Raw                 : {_hex_preview(response, max_chars=120)}")
        return
    rules = decode_rat_rules(response)
    print(f"    | Rules               : {len(rules)}")
    if len(rules) == 0:
        return
    first_rule = rules[0]
    if "pprIdsRaw" in first_rule:
        print(f"    | PPR IDs Raw         : {first_rule['pprIdsRaw']}")
    if "pprIds" in first_rule:
        print(f"    | PPR IDs Meaning     : {first_rule['pprIds']}")
    operators = first_rule.get("allowedOperators", [])
    print(f"    | Allowed Operators   : {len(operators) if isinstance(operators, list) else 0}")
    if isinstance(operators, list) and len(operators) > 0:
        operator = operators[0]
        details: list[str] = []
        if "mccMnc" in operator:
            details.append(f"mccMnc={operator['mccMnc']}")
        if "gid1" in operator:
            details.append(f"gid1={operator['gid1']}")
        if "gid2" in operator:
            details.append(f"gid2={operator['gid2']}")
        print(f"    | First Operator      : {', '.join(details)}")


def _print_notifications_list_compact(response: bytes) -> None:
    print("\n[+] RetrieveNotificationsList")
    if len(response) == 0:
        print("    | (Empty)")
        return
    if decode_notifications_response is None:
        print(f"    | Raw                 : {_hex_preview(response, max_chars=120)}")
        return
    decoded = decode_notifications_response(response)
    notifications = decoded.get("notifications", [])
    package_results = decoded.get("package_results", [])
    error_text = str(decoded.get("error", "")).strip()
    if len(error_text) > 0:
        print(f"    | Result              : {error_text}")
        return
    print(f"    | Notification Entries: {len(notifications)}")
    if len(package_results) > 0:
        print(f"    | Package Results     : {len(package_results)}")
    if len(notifications) == 0:
        return
    first = notifications[0]
    if "seqNumber" in first:
        print(f"    | Seq Number          : {first['seqNumber']}")
    if "operation" in first:
        print(f"    | Operation           : {first['operation']}")
    if "notificationAddress" in first:
        print(f"    | Server/FQDN         : {first['notificationAddress']}")
    if "iccid" in first:
        print(f"    | ICCID               : {first['iccid']}")


def _print_eim_configuration_compact(response: bytes) -> None:
    print("\n[+] GetEimConfigurationData")
    if len(response) == 0:
        print("    | (Empty)")
        return
    if decode_eim_configuration_entries is None:
        print(f"    | Raw                 : {_hex_preview(response, max_chars=120)}")
        return
    entries = decode_eim_configuration_entries(response)
    print(f"    | eIM Entries         : {len(entries)}")
    if len(entries) == 0:
        return
    first = entries[0]
    fqdn = str(first.get("eim_fqdn", "")).strip()
    eim_id = str(first.get("eim_id", "")).strip()
    if len(fqdn) > 0:
        print(f"    | First eIM FQDN      : {fqdn}")
    if len(eim_id) > 0:
        print(f"    | First eIM ID        : {eim_id}")


def _print_get_certs_compact(response: bytes) -> None:
    print("\n[+] GetCerts")
    if len(response) == 0:
        print("    | (Empty)")
        return
    if decode_get_certs_response is None:
        print(f"    | Raw                 : {_hex_preview(response, max_chars=120)}")
        return
    decoded = decode_get_certs_response(response)
    if len(decoded) == 0:
        print(f"    | Raw                 : {_hex_preview(response, max_chars=120)}")
        return
    if "error" in decoded:
        print(f"    | Result              : {decoded['error']}")
        return
    eum = decoded.get("eumCertificate", b"")
    euicc = decoded.get("euiccCertificate", b"")
    print(f"    | EUM Certificate     : {'Present' if isinstance(eum, bytes) and len(eum) > 0 else 'Absent'}")
    print(f"    | eUICC Certificate   : {'Present' if isinstance(euicc, bytes) and len(euicc) > 0 else 'Absent'}")
    if isinstance(eum, bytes) and len(eum) > 0:
        print(f"    | EUM Cert Bytes      : {len(eum)}")
    if isinstance(euicc, bytes) and len(euicc) > 0:
        print(f"    | eUICC Cert Bytes    : {len(euicc)}")


def render_consolidated_discovery_snapshot(
    snapshot: dict[str, Any],
    *,
    header_color: str = "",
    end_color: str = "",
) -> None:
    print(f"\n{header_color}=== SGP.32 Consolidated Data Retrieval ==={end_color}")
    print(f"\n{header_color}=== Running SGP.22/SGP.32 Scan ==={end_color}")

    eid = str(snapshot.get("eid", "")).strip()
    print("\n[+] EID")
    print(f"    | Value               : {eid or '(unavailable)'}")

    profiles = snapshot.get("profiles", [])
    if isinstance(profiles, list) is False:
        profiles = []
    _print_profiles_table(profiles)

    configured_decoded = snapshot.get("configured_decoded", {})
    if isinstance(configured_decoded, dict) is False:
        configured_decoded = {}
    _print_configured_status_from_decoded(configured_decoded, _as_bytes(snapshot.get("configured_raw", b"")))
    _print_euicc_info1_compact(_as_bytes(snapshot.get("euicc_info1", b"")))
    _print_euicc_info2_compact(_as_bytes(snapshot.get("euicc_info2", b"")))
    _print_rat_compact(_as_bytes(snapshot.get("rat", b"")))
    _print_notifications_list_compact(_as_bytes(snapshot.get("notifications", b"")))
    _print_eim_configuration_compact(_as_bytes(snapshot.get("eim_configuration", b"")))
    _print_get_certs_compact(_as_bytes(snapshot.get("certs", b"")))
