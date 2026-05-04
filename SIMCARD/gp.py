from __future__ import annotations

from SIMCARD.etsi_fs import USIM_AID, ISIM_AID
from SIMCARD.state import SimCardState, SimGpAppEntry, SimGpInstallContext
from SIMCARD.utils import tlv


# GP Card Spec v2.3.1 §11.1.1 / §11.1.2 lifecycle constants. The
# simulator only needs the values it can return; everything else is
# treated as opaque.
GP_LCS_LOADED = 0x01
GP_LCS_INSTALLED = 0x03
GP_LCS_SELECTABLE = 0x07
GP_LCS_PERSONALIZED = 0x0F
GP_LCS_LOCKED_APPLICATION = 0x83
GP_LCS_SD_PERSONALIZED = 0x0F
GP_LCS_SD_LOCKED = 0x7F


class SimulatedSecureSession:
    """Fallback secure session for simulator paths that remain plaintext."""

    def __init__(self, protocol_name: str = "SCP03") -> None:
        self.protocol_name = str(protocol_name or "SCP03").strip().upper() or "SCP03"
        self.is_authenticated = True
        self.chaining_value = b"\x00" * 16
        self.ssc = 0

    def reset_state(self) -> None:
        self.is_authenticated = False
        self.chaining_value = b"\x00" * 16
        self.ssc = 0

    def wrap_apdu(self, apdu):
        return list(apdu)

    def unwrap_response(self, data: bytes, sw1: int, sw2: int) -> bytes:
        del sw1, sw2
        return bytes(data)

    def encrypt_key_data(self, key_bytes: bytes) -> bytes:
        return bytes(key_bytes)


class GpLogic:
    """GP Card Spec v2.3.1 §11 dispatcher.

    Coverage:

    - 0xCA GET DATA (limited tag set)
    - 0xF2 GET STATUS  (P1 = 0x80 / 0x40 / 0x20 / 0x10 / 0x60)
    - 0xE6 INSTALL     (P1 sub-functions 0x02 / 0x04 / 0x08 / 0x0C / 0x10 / 0x20 / 0x40)
    - 0xE8 LOAD        (block-chained CAP file delivery)
    - 0xE4 DELETE      (object / object+related)
    - 0xD8 PUT KEY     (record-only; cryptography stays in Scp03CardLogic)
    - 0xF0 SET STATUS  (lifecycle change)

    INSTALL/LOAD/DELETE/PUT KEY/SET STATUS require an authenticated
    SCP03 session; the engine gates that before the dispatch reaches
    this class. PUT KEY validation is intentionally lenient: the
    simulator records the request so a test harness can inspect it
    without owning the host-side decryption keys.
    """

    def __init__(self, state: SimCardState) -> None:
        self.state = state

    # ------------------------------------------------------------------
    # GET DATA / GET STATUS
    # ------------------------------------------------------------------

    def handle_get_data(self, p1: int, p2: int) -> tuple[bytes, int, int]:
        tag_hex = f"{p1:02X}{p2:02X}"
        if tag_hex == "005A":
            return tlv("5A", bytes.fromhex(self.state.eid)), 0x90, 0x00
        if tag_hex == "00E0":
            return self._build_key_information_template(), 0x90, 0x00
        if tag_hex == "FF40":
            return tlv("FF40", b""), 0x90, 0x00
        if tag_hex == "0042":
            # GP Card Spec v2.3.1 §H.4 IIN. Derived from the first
            # 4 bytes (8 hex digits) of the EID; the simulator does not
            # expose a separate IIN slot but commercial cards almost
            # always carry the eUICC manufacturer/issuer prefix here.
            iin_bytes = self._issuer_identification_bytes()
            return tlv("42", iin_bytes), 0x90, 0x00
        if tag_hex == "0045":
            # GP Card Spec v2.3.1 §H.5 CIN. Reuses the EID as the card
            # image number to keep the value deterministic and unique.
            return tlv("45", bytes.fromhex(self.state.eid)), 0x90, 0x00
        if tag_hex == "0066":
            # GP Card Spec v2.3.1 §H.2 Card Recognition Data. Wrapped in
            # the constructed application tag 73 inside the outer
            # primitive tag 66 (`Card Data` per ISO 7816-6).
            return tlv("66", self._build_card_recognition_data()), 0x90, 0x00
        if tag_hex == "9F7F":
            # GP Card Spec v2.3.1 §11.4 / TS 102 226 CPLC. 42 raw bytes
            # under tag 9F7F; modems and personalisation tools probe
            # this universally to fingerprint a card.
            return tlv("9F7F", self._build_cplc_blob()), 0x90, 0x00
        if tag_hex == "FF21":
            # GP Card Spec v2.3.1 Amendment B §H.6 Extended Card
            # Resources. Same shape as the E0 sub-template in the
            # ISD-R FCI: 81 system-app count, 82 free NVM (3 bytes),
            # 83 free RAM (2 bytes). RAM management tools (STORE-DATA
            # admin paths, the GSMA SAS-UP loader) probe this to
            # decide whether a CAP file fits before issuing INSTALL
            # [for load].
            return tlv("FF21", self._build_extended_card_resources()), 0x90, 0x00
        return b"", 0x6A, 0x88

    def handle_get_status(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        del p2
        scope = int(p1) & 0xFF
        search_aid = self._extract_search_aid(bytes(data or b""))

        if scope == 0x80:
            entries = [
                self._status_entry(self.state.isdr_aid, GP_LCS_SD_PERSONALIZED, bytes.fromhex("9EFE80")),
                self._status_entry(self.state.ecasd_aid, GP_LCS_SD_PERSONALIZED, bytes.fromhex("9EFE80")),
                self._status_entry(self.state.mno_sd_aid, GP_LCS_SELECTABLE, bytes.fromhex("80")),
            ]
            return self._filtered_status_response(entries, search_aid)

        if scope == 0x40:
            entries: list[bytes] = [
                self._status_entry(USIM_AID, GP_LCS_SELECTABLE, b""),
                self._status_entry(ISIM_AID, GP_LCS_SELECTABLE, b""),
            ]
            entries.extend(
                self._status_entry(profile.aid, GP_LCS_SELECTABLE, b"") for profile in self.state.profiles
            )
            entries.extend(
                self._status_entry(app.aid, app.lifecycle_state, app.privileges)
                for app in self.state.gp_apps
                if app.kind == "application"
            )
            return self._filtered_status_response(entries, search_aid)

        if scope == 0x10:
            entries = [
                self._status_entry(app.aid, app.lifecycle_state, b"")
                for app in self.state.gp_apps
                if app.kind == "elf"
            ]
            return self._filtered_status_response(entries, search_aid)

        if scope == 0x20:
            entries = [
                self._status_entry(app.aid, app.lifecycle_state, b"")
                for app in self.state.gp_apps
                if app.kind == "module"
            ]
            return self._filtered_status_response(entries, search_aid)

        if scope == 0x60:
            entries = []
            for app in self.state.gp_apps:
                if app.kind == "elf":
                    body = tlv("4F", bytes.fromhex(app.aid)) + tlv("9F70", bytes([app.lifecycle_state & 0xFF]))
                    for module_aid in app.modules:
                        if len(module_aid) == 0:
                            continue
                        body += tlv("84", bytes.fromhex(module_aid))
                    entries.append(tlv("E3", body))
            return self._filtered_status_response(entries, search_aid)

        return b"", 0x6A, 0x86

    # ------------------------------------------------------------------
    # INSTALL / LOAD / DELETE / PUT KEY / SET STATUS
    # ------------------------------------------------------------------

    def handle_install(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        sub_function = int(p1) & 0xFF
        more_blocks = (int(p2) & 0x80) == 0
        del more_blocks  # multi-block INSTALL is rare and not modelled

        if sub_function == 0x02:
            return self._install_for_load(bytes(data or b""))
        if sub_function == 0x04:
            return self._install_for_install(bytes(data or b""), make_selectable=False)
        if sub_function == 0x08:
            return self._install_for_make_selectable(bytes(data or b""))
        if sub_function == 0x0C:
            return self._install_for_install(bytes(data or b""), make_selectable=True)
        if sub_function == 0x10:
            return self._install_for_extradition(bytes(data or b""))
        if sub_function == 0x20:
            return self._install_for_personalization(bytes(data or b""))
        if sub_function == 0x40:
            return self._install_for_registry_update(bytes(data or b""))
        return b"", 0x6A, 0x86

    def handle_load(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        last_block = (int(p1) & 0x80) != 0
        block_number = int(p2) & 0xFF
        ctx: SimGpInstallContext = self.state.gp_install
        if len(ctx.pending_elf_aid) == 0:
            return b"", 0x69, 0x85
        if block_number != ctx.expected_block:
            ctx.load_buffer = b""
            ctx.expected_block = 0
            return b"", 0x6A, 0x80

        ctx.load_buffer += bytes(data or b"")
        ctx.expected_block = (ctx.expected_block + 1) & 0xFF

        if last_block is False:
            return b"", 0x90, 0x00

        elf_entry = SimGpAppEntry(
            aid=ctx.pending_elf_aid,
            kind="elf",
            lifecycle_state=GP_LCS_LOADED,
            privileges=b"",
        )
        self._upsert_app(elf_entry)
        ctx.last_block_seen = True
        ctx.pending_elf_aid = ""
        ctx.pending_sd_aid = ""
        ctx.expected_block = 0
        ctx.load_buffer = b""
        return b"", 0x90, 0x00

    def handle_delete(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        del p1
        delete_related = (int(p2) & 0x80) != 0
        payload = bytes(data or b"")
        if len(payload) < 2 or payload[0] != 0x4F:
            return b"", 0x6A, 0x80
        aid_length = payload[1]
        if 2 + aid_length > len(payload):
            return b"", 0x6A, 0x80
        target_aid = payload[2 : 2 + aid_length].hex().upper()
        if len(target_aid) == 0:
            return b"", 0x6A, 0x82
        target_app = self._find_app(target_aid)
        if target_app is None:
            return b"", 0x6A, 0x82
        # GP Card Spec §11.2.2.4: an SD or an ELF that still has
        # dependants cannot be deleted unless P2 bit 0x80 is set.
        if delete_related is False:
            for app in self.state.gp_apps:
                if app is target_app:
                    continue
                if app.associated_elf.upper() == target_aid:
                    return b"", 0x6A, 0x88
        retained: list[SimGpAppEntry] = []
        for app in self.state.gp_apps:
            if app is target_app:
                continue
            if delete_related and (
                app.associated_elf.upper() == target_aid
                or any(module.upper() == target_aid for module in app.modules)
            ):
                continue
            retained.append(app)
        self.state.gp_apps = retained
        return b"", 0x90, 0x00

    def handle_put_key(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        del data
        kvn = int(p1) & 0xFF
        key_id = int(p2) & 0xFF
        if kvn == 0x00 and key_id == 0x00:
            return b"", 0x6A, 0x86
        # The simulator's static keys live in :class:`Scp03CardLogic`
        # and are not rotated through this path. Returning 90 00 lets
        # tooling exercise the wire format without making the
        # simulator pretend it has accepted a re-keyed bundle.
        return bytes([kvn]), 0x90, 0x00

    def handle_set_status(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        scope = int(p1) & 0xFF
        new_state = int(p2) & 0xFF
        payload = bytes(data or b"")
        if len(payload) == 0:
            return b"", 0x6A, 0x80
        # GP Card Spec §11.10: the data field carries the AID of the
        # target object, NOT a 4F-prefixed TLV.
        target_aid = payload.hex().upper()

        if scope == 0x80:
            for sd_aid in (self.state.isdr_aid, self.state.ecasd_aid, self.state.mno_sd_aid):
                if str(sd_aid or "").upper() == target_aid:
                    return b"", 0x90, 0x00
            return b"", 0x6A, 0x82

        target = self._find_app(target_aid)
        if target is None:
            return b"", 0x6A, 0x82
        target.lifecycle_state = new_state
        return b"", 0x90, 0x00

    # ------------------------------------------------------------------
    # INSTALL sub-function helpers
    # ------------------------------------------------------------------

    def _install_for_load(self, data: bytes) -> tuple[bytes, int, int]:
        offset, elf_aid = self._take_lv(data, 0)
        if offset is None:
            return b"", 0x6A, 0x80
        offset, sd_aid = self._take_lv(data, offset)
        if offset is None:
            return b"", 0x6A, 0x80

        ctx = self.state.gp_install
        ctx.pending_elf_aid = elf_aid.hex().upper()
        ctx.pending_sd_aid = sd_aid.hex().upper()
        ctx.load_buffer = b""
        ctx.expected_block = 0
        ctx.last_block_seen = False
        return b"", 0x90, 0x00

    def _install_for_install(self, data: bytes, *, make_selectable: bool) -> tuple[bytes, int, int]:
        offset, elf_aid = self._take_lv(data, 0)
        if offset is None:
            return b"", 0x6A, 0x80
        offset, module_aid = self._take_lv(data, offset)
        if offset is None:
            return b"", 0x6A, 0x80
        offset, app_aid = self._take_lv(data, offset)
        if offset is None or len(app_aid) == 0:
            return b"", 0x6A, 0x80
        offset, privileges = self._take_lv(data, offset)
        if offset is None:
            privileges = b""

        elf_aid_hex = elf_aid.hex().upper()
        module_aid_hex = module_aid.hex().upper()
        app_aid_hex = app_aid.hex().upper()

        elf = self._find_app(elf_aid_hex)
        if elf is None or elf.kind != "elf":
            return b"", 0x6A, 0x82
        if len(module_aid_hex) > 0 and module_aid_hex not in [m.upper() for m in elf.modules]:
            elf.modules.append(module_aid_hex)
            self._upsert_app(
                SimGpAppEntry(
                    aid=module_aid_hex,
                    kind="module",
                    lifecycle_state=GP_LCS_SELECTABLE,
                    associated_elf=elf_aid_hex,
                )
            )

        new_app = SimGpAppEntry(
            aid=app_aid_hex,
            kind="application",
            lifecycle_state=GP_LCS_SELECTABLE if make_selectable else GP_LCS_INSTALLED,
            privileges=bytes(privileges or b""),
            associated_elf=elf_aid_hex,
        )
        self._upsert_app(new_app)
        return b"", 0x90, 0x00

    def _install_for_make_selectable(self, data: bytes) -> tuple[bytes, int, int]:
        offset, app_aid = self._take_lv(data, 0)
        if offset is None or len(app_aid) == 0:
            return b"", 0x6A, 0x80
        target = self._find_app(app_aid.hex().upper())
        if target is None or target.kind != "application":
            return b"", 0x6A, 0x82
        target.lifecycle_state = GP_LCS_SELECTABLE
        return b"", 0x90, 0x00

    def _install_for_extradition(self, data: bytes) -> tuple[bytes, int, int]:
        # GP Card Spec §11.5.2.7. The simulator does not multiplex SDs,
        # so we acknowledge the request without rebinding the target.
        del data
        return b"", 0x90, 0x00

    def _install_for_personalization(self, data: bytes) -> tuple[bytes, int, int]:
        # §11.5.2.8: hands the next STORE DATA chain to the named app.
        # The SgpLogic STORE DATA dispatcher does not key off the
        # personalization target, so the request is accepted as-is.
        del data
        return b"", 0x90, 0x00

    def _install_for_registry_update(self, data: bytes) -> tuple[bytes, int, int]:
        del data
        return b"", 0x90, 0x00

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    @staticmethod
    def _take_lv(data: bytes, offset: int) -> tuple[int | None, bytes]:
        """LV (Length-Value) reader with bounds checks."""
        if offset >= len(data):
            return None, b""
        length = data[offset]
        start = offset + 1
        end = start + length
        if end > len(data):
            return None, b""
        return end, data[start:end]

    def _find_app(self, aid_hex: str) -> SimGpAppEntry | None:
        target = str(aid_hex or "").strip().upper()
        for app in self.state.gp_apps:
            if str(app.aid or "").upper() == target:
                return app
        return None

    def _upsert_app(self, candidate: SimGpAppEntry) -> None:
        target = candidate.aid.upper()
        for index, existing in enumerate(self.state.gp_apps):
            if existing.aid.upper() == target:
                self.state.gp_apps[index] = candidate
                return
        self.state.gp_apps.append(candidate)

    @staticmethod
    def _extract_search_aid(payload: bytes) -> bytes:
        if len(payload) >= 2 and payload[0] == 0x4F:
            length = payload[1]
            if 2 + length <= len(payload):
                return payload[2 : 2 + length]
        return b""

    @staticmethod
    def _filtered_status_response(
        entries: list[bytes],
        search_aid: bytes,
    ) -> tuple[bytes, int, int]:
        if len(search_aid) == 0:
            return b"".join(entries), 0x90, 0x00
        target_hex = search_aid.hex().upper()
        kept: list[bytes] = []
        for entry in entries:
            if target_hex in entry.hex().upper():
                kept.append(entry)
        if len(kept) == 0:
            return b"", 0x6A, 0x88
        return b"".join(kept), 0x90, 0x00

    def _build_key_information_template(self) -> bytes:
        kvn = int(self.state.scp03_session.key_version) & 0xFF
        entries = []
        for key_id in (1, 2, 3):
            entries.append(bytes([0xC0, 0x04, key_id, kvn, 0x88, 0x10]))
        return b"".join(entries)

    def _issuer_identification_bytes(self) -> bytes:
        """GP §H.4 IIN derived from the EID prefix (4 bytes / 8 digits)."""
        eid_hex = (self.state.eid or "").strip().upper()
        normalized = eid_hex.ljust(8, "0")[:8]
        try:
            return bytes.fromhex(normalized)
        except ValueError:
            return b"\x00\x00\x00\x00"

    def _build_card_recognition_data(self) -> bytes:
        """GP Card Spec v2.3.1 §H.2 Card Recognition Data.

        Encodes the constructed `73` application template with a
        minimum-viable but spec-correct OID set:

        - 06 OID identifying CRD itself           (1.2.840.114283.1.0)
        - 60 [APP 0] card management type/version (1.2.840.114283.2.2.3.1)
        - 63 [APP 3] card identification scheme   (1.2.840.114283.3)
        - 64 [APP 4] secure channel protocol      (1.2.840.114283.4.3.<i>)
        - 65 [APP 5] card configuration details   (empty placeholder)
        - 66 [APP 6] card / chip details          (empty placeholder)

        ``i`` follows the SCP03 implementation byte (0x70 = pseudo-random
        challenge + RMAC, the simulator default).
        """
        crd_oid = bytes.fromhex("2A864886FC6B0100")
        gp_version_oid = bytes.fromhex("2A864886FC6B02020301")
        cid_scheme_oid = bytes.fromhex("2A864886FC6B03")
        scp03_i_byte = int(getattr(self.state.scp03_session, "i_byte", 0x70)) & 0xFF
        scp_oid = bytes.fromhex("2A864886FC6B0403") + bytes([scp03_i_byte])
        body = tlv("06", crd_oid)
        body += tlv("60", tlv("06", gp_version_oid))
        body += tlv("63", tlv("06", cid_scheme_oid))
        body += tlv("64", tlv("06", scp_oid))
        body += tlv("65", b"")
        body += tlv("66", b"")
        return tlv("73", body)

    def _build_extended_card_resources(self) -> bytes:
        """GP Card Spec v2.3.1 Amendment B §H.6 Extended Card Resources.

        Mirrors :class:`SimEuiccExtCardResources`: byte count of the
        installed system applications (81), free non-volatile memory
        in bytes (82, 3-byte big-endian), free volatile memory in
        bytes (83, 2-byte big-endian).
        """
        ext = self.state.euicc_info.ext_card_resources
        return (
            tlv("81", bytes([int(ext.system_apps_count) & 0xFF]))
            + tlv("82", int(ext.free_nvm).to_bytes(3, "big", signed=False))
            + tlv("83", int(ext.free_ram).to_bytes(2, "big", signed=False))
        )

    def _build_cplc_blob(self) -> bytes:
        """TS 102 226 / GP §H Card Production Lifecycle Data.

        Returns a 42-byte CPLC seeded from the EID + ICCID so the value
        is deterministic per simulator instance. None of the fields are
        meaningful for production but the layout matches commercial
        UICCs so probing tools (PCSC scriptors, modem fingerprinters)
        accept the response.
        """
        eid = (self.state.eid or "").strip().upper().ljust(32, "0")[:32]
        iccid = (self.state.iccid or "").strip().upper().ljust(20, "0")[:20]
        try:
            eid_bytes = bytes.fromhex(eid)
        except ValueError:
            eid_bytes = b"\x00" * 16
        try:
            iccid_bytes = bytes.fromhex(iccid)
        except ValueError:
            iccid_bytes = b"\x00" * 10
        ic_serial = (eid_bytes[12:16]).ljust(4, b"\x00")[:4]
        ic_batch = (eid_bytes[10:12]).ljust(2, b"\x00")[:2]
        cplc = b""
        cplc += b"\x47\x91"  # IC Fabricator (Infineon-shaped placeholder)
        cplc += b"\x50\x40"  # IC Type
        cplc += b"\x47\x91"  # OS ID
        cplc += b"\x60\x01"  # OS Release Date (BCD YDDD)
        cplc += b"\x00\x01"  # OS Release Level
        cplc += b"\x60\x01"  # IC Fabrication Date
        cplc += ic_serial    # IC Serial Number (4)
        cplc += ic_batch     # IC Batch ID (2)
        cplc += b"\x47\x91"  # IC Module Fabricator
        cplc += b"\x60\x01"  # IC Module Packaging Date
        cplc += b"\x47\x91"  # ICC Manufacturer
        cplc += b"\x60\x01"  # IC Embedding Date
        cplc += b"\x47\x91"  # IC Pre-Personalizer
        cplc += b"\x60\x01"  # IC Pre-Personalization Date
        cplc += iccid_bytes[:4].ljust(4, b"\x00")  # IC Pre-Personalization Equipment ID
        cplc += b"\x47\x91"  # IC Personalizer
        cplc += b"\x60\x01"  # IC Personalization Date
        cplc += iccid_bytes[4:8].ljust(4, b"\x00")  # IC Personalization Equipment ID
        return cplc

    @staticmethod
    def _status_entry(aid_hex: str, life_cycle_state: int, privileges: bytes) -> bytes:
        body = tlv("4F", bytes.fromhex(aid_hex)) + tlv("9F70", bytes([life_cycle_state & 0xFF]))
        if len(privileges) > 0:
            body += tlv("C5", bytes(privileges))
        return tlv("E3", body)
