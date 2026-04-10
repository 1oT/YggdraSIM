"""Optional simulator quirks file.

This file is loaded only when the wrapper selects the simulated card backend.
You can either expose individual hook functions, define register_quirks(registry),
or provide metadata overrides for the simulator personality.

Available hooks:
    configure_state(state) -> None
    before_apdu(apdu: bytes, state) -> tuple[data: bytes, sw1: int, sw2: int] | None
    after_apdu(apdu: bytes, result, state) -> tuple[data: bytes, sw1: int, sw2: int] | None
    on_reset(state) -> None

Supported metadata override entry points:
    metadata_overrides = {
        "default_dp_address": "rsp.custom.test",
        "root_ci_pkid": "00112233445566778899AABBCCDDEEFF00112233",
        "euicc_info": {
            "ipa_mode": 0,
            "info1_svn": "010203",
            "iot_specific_info": {
                "iot_versions": ["070809"],
                "ecall_supported": True,
                "fallback_supported": True,
            },
        },
        "configured_data": {
            "root_smds_address": "smds.custom.test",
            "additional_root_smds_addresses": ["backup.custom.test"],
        },
        "eim_entries": [
            {
                "eim_id": "manager-custom",
                "eim_fqdn": "eim.custom.test",
                "eim_id_type": 3,
                "supported_protocol_bits": [0, 4],
            }
        ],
        "eum_certificate_der": "<DER hex>",
        "euicc_certificate_der": "<DER hex>",
    }
"""


# Keep this empty by default so a freshly seeded quirks file does not alter the
# simulator personality until you opt in with explicit overrides.
metadata_overrides = {}


def register_quirks(registry):
    # Example: force MANAGE CHANNEL to behave as unsupported even if the core
    # simulator gains support for it later.
    def before_apdu(apdu, state):
        del state
        if len(apdu) >= 2 and apdu[1] == 0x70:
            return b"", 0x68, 0x81
        return None

    registry.add_before_apdu(before_apdu)
