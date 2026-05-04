"""Optional simulator quirks file (no-op default).

This file is loaded only when the wrapper selects the simulated card backend
AND the environment opts in via YGGDRASIM_ALLOW_QUIRKS=1. The gate exists
because quirk files are executed as Python on startup; never point the
simulator at a quirk file from an untrusted source.

The shipped default is intentionally empty: a freshly seeded
``Workspace/SIMCARD/sim_quirks.py`` installs no APDU hooks and declares no
metadata overrides. The simulator therefore runs on its built-in personality
until you edit this file to add explicit behaviour.

Quick kill switches (no edits needed):

* ``YGGDRASIM_SIM_QUIRKS=none`` - skip this file entirely, boot with an
  empty quirks registry.
* ``YGGDRASIM_DISABLE_QUIRKS=1`` - process-wide kill switch; simulator
  skips quirks loading regardless of the configured path.

Available hooks (declare any subset; all optional):

    configure_state(state) -> None
    before_apdu(apdu: bytes, state) -> tuple[data: bytes, sw1: int, sw2: int] | None
    after_apdu(apdu: bytes, result, state) -> tuple[data: bytes, sw1: int, sw2: int] | None
    on_reset(state) -> None
    register_quirks(registry) -> None     # programmatic hook registration

Supported metadata override entry points (top-level module attributes):

    metadata_overrides = {
        "atr": "3B9F96801FC78031A073BE21136743200718000001A5",
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

Example - force MANAGE CHANNEL (INS=0x70) to return "channel not supported"
(6881) regardless of whether the core simulator gains native support later.
Uncomment the block below to install it.

    def register_quirks(registry):
        def before_apdu(apdu, state):
            del state
            if len(apdu) >= 2 and apdu[1] == 0x70:
                return b"", 0x68, 0x81
            return None

        registry.add_before_apdu(before_apdu)
"""


# No overrides by default - the simulator keeps its built-in personality.
metadata_overrides = {}
