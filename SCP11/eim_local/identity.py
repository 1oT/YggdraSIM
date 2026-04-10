import json
import os
from typing import Any


DEFAULT_EIM_IDENTITY: dict[str, str] = {
    "display_name": "Local eIM Identity (certificate material not bundled)",
    "eim_id": "2.25.311782205282738360923618091971140414400",
    "eim_id_type": "oid",
    "eim_fqdn": "yggdrasim.eim.test.1ot.com",
    "default_matching_id": "EIM-FIRST-TEST",
    "organization": "RSPTEST",
    "certificate_subject_cn": "yggdrasim.eim.test.1ot.com",
    "eim_endpoint": "https://yggdrasim.eim.test.1ot.com/gsma/rsp2/asn1",
    "smdpp_endpoint": "https://yggdrasim.smdpp.test.1ot.com/gsma/rsp2/es9plus",
    "smdp_address": "yggdrasim.smdpp.test.1ot.com",
    "eim_public_key_cert_path": "",
    "trusted_tls_cert_path": "",
    "tls_private_key_path": "",
    "euicc_ci_pk_id": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
}


def load_eim_identity(file_path: str) -> dict[str, str]:
    identity = dict(DEFAULT_EIM_IDENTITY)
    candidate = str(file_path or "").strip()
    if len(candidate) == 0:
        return identity
    if os.path.isfile(candidate) is False:
        return identity
    try:
        with open(candidate, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return identity
    if isinstance(payload, dict) is False:
        return identity
    for key in identity.keys():
        value: Any = payload.get(key)
        if isinstance(value, str):
            cleaned = value.strip()
            if len(cleaned) > 0:
                identity[key] = cleaned
    return identity
