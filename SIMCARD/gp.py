# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""GlobalPlatform card-side logic: SSD secure session emulation, INSTALL/LOAD/DELETE command dispatch (GP Card Spec v2.3)."""
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

# Upper bound on the reassembled INSTALL data field (§11.5.2.1 P1.b8
# segmentation). Tables 11-42 to 11-46 cap a single BER-coded field at
# '82 FF FF', so a chain that passes this is malformed rather than long.
MAX_INSTALL_CHAIN_BYTES = 0x10000

# Upper bound on the reassembled DELETE data field (§11.2.2.1 P1.b8
# segmentation). Table 11-23 carries one AID, a Control Reference Template and
# a token, so a longer chain is malformed rather than long.
MAX_DELETE_CHAIN_BYTES = 0x4000


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
    - 0xF2 GET STATUS  (P1 = 0x80 ISD / 0x40 applications and SSDs /
      0x20 Executable Load Files / 0x10 those plus their Executable
      Modules / 0x60 as 0x10, Table 11-33)
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
        # §11.5.2.1 P1.b8 segmentation buffer. Reset on every
        # dispatched INSTALL, so it holds at most one command chain.
        self._install_chain: bytes = b""
        self._delete_chain: bytes = b""

    # ------------------------------------------------------------------
    # GET DATA / GET STATUS
    # ------------------------------------------------------------------

    def handle_get_data(self, p1: int, p2: int) -> tuple[bytes, int, int]:
        """GP Card Spec v2.3 §11.3 GET DATA -- returns card/SD status data objects.

        Supported tags: 005A (EID), 9F7F (CPLC), 9F70 (card life-cycle state).
        """
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
        """GP Card Spec v2.3.1 §11.4 GET STATUS -- reports installed applications and SDs.

        §11.4.2.1 P1: '80' Issuer Security Domain, '40' Applications
        including Supplementary Security Domains, '20' Executable Load
        Files only, '10' Executable Load Files and their Executable
        Modules. §11.4.2.2 P2.b1 selects first/next occurrences and
        P2.b2 selects the Table 11-36 / 11-37 response format; the
        simulator returns every match in one response, so a [get next
        occurrence] request has nothing left to report.
        """
        scope = int(p1) & 0xFF
        if (int(p2) & 0x01) != 0:
            # Table 11-38 '63 10' (more data) is never returned, so the
            # follow-up read has no occurrences left: §11.4.3.2 '6A 88'.
            return b"", 0x6A, 0x88
        search_aid = self._extract_search_aid(bytes(data or b""))

        if scope == 0x80:
            # §11.4.2.1: '80' reports the Issuer Security Domain only, and any
            # search criteria in the data field are ignored. On an eUICC the
            # ISD-R is that domain; ECASD and the MNO-SD are supplementary and
            # are reported under '40'.
            entries: list[tuple[str, bytes]] = [
                self._registry_entry(self.state.isdr_aid, GP_LCS_SD_PERSONALIZED, bytes.fromhex("9EFE80")),
            ]
            return self._filtered_status_response(entries, b"")

        if scope == 0x40:
            # §11.4.2.1: '40' reports Applications and Supplementary Security
            # Domains; the privileges byte tells the two apart (table 11-7 b8).
            entries = [
                self._registry_entry(self.state.ecasd_aid, GP_LCS_SD_PERSONALIZED, bytes.fromhex("9EFE80")),
                self._registry_entry(self.state.mno_sd_aid, GP_LCS_SELECTABLE, bytes.fromhex("80")),
                self._registry_entry(USIM_AID, GP_LCS_SELECTABLE, b""),
                self._registry_entry(ISIM_AID, GP_LCS_SELECTABLE, b""),
            ]
            entries.extend(
                self._registry_entry(profile.aid, GP_LCS_SELECTABLE, b"") for profile in self.state.profiles
            )
            entries.extend(
                self._registry_entry(app.aid, app.lifecycle_state, app.privileges)
                for app in self.state.gp_apps
                if app.kind == "application"
            )
            return self._filtered_status_response(entries, search_aid)

        if scope in (0x20, 0x10, 0x60):
            # Table 11-37 Note 2: the Executable Module AIDs (tag '84')
            # are listed under their Executable Load File and only when
            # P1.b5 asks for them. §11.4.2.1 leaves a multi-bit P1
            # implementation dependent; '60' keeps the load-file view
            # with modules that this simulator has always exposed.
            with_modules = (scope & 0x10) != 0 or scope == 0x60
            entries = [
                self._load_file_entry(app, with_modules=with_modules)
                for app in self.state.gp_apps
                if app.kind == "elf"
            ]
            return self._filtered_status_response(entries, search_aid)

        return b"", 0x6A, 0x86

    # ------------------------------------------------------------------
    # INSTALL / LOAD / DELETE / PUT KEY / SET STATUS
    # ------------------------------------------------------------------

    def handle_install(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        """GP Card Spec v2.3.1 §11.5 INSTALL -- records install parameters in the GP context.

        Table 11-41 codes P1.b8 as the segmentation flag (1 = more
        INSTALL commands follow, 0 = last or only component) and
        P1.b7..b2 as the sub-function; b1 is always 0. Table 11-40
        restricts P2 to '00' (no information), '01' (beginning of the
        combined load, install and make selectable process) and '03'
        (end of that process) -- P2 never carried the segmentation
        flag.
        """
        p1_byte = int(p1) & 0xFF
        p2_byte = int(p2) & 0xFF
        if p2_byte not in (0x00, 0x01, 0x03):
            return b"", 0x6A, 0x86

        sub_function = p1_byte & 0x7E
        payload = self._install_chain + bytes(data or b"")
        if len(payload) > MAX_INSTALL_CHAIN_BYTES:
            self._install_chain = b""
            return b"", 0x6A, 0x80
        if (p1_byte & 0x80) != 0:
            # Segmented command data: hold the component and answer
            # 90 00 until the last one arrives. The buffer is reset on
            # every dispatch and capped at MAX_INSTALL_CHAIN_BYTES, so
            # an unterminated chain cannot grow without bound.
            self._install_chain = payload
            return b"", 0x90, 0x00
        self._install_chain = b""

        # Table 11-41 gives [for registry update], [for personalization]
        # and [for extradition] as exclusive sub-functions; only [for
        # load], [for install] and [for make selectable] combine.
        if sub_function == 0x40:
            return self._install_for_registry_update(payload)
        if sub_function == 0x20:
            return self._install_for_personalization(payload)
        if sub_function == 0x10:
            return self._install_for_extradition(payload)
        if (sub_function & 0x02) != 0:
            # §11.5.2.3.1: the first command of a combined [for load,
            # install and make selectable] carries the Table 11-42
            # data field, same as a plain INSTALL [for load].
            return self._install_for_load(payload)
        if (sub_function & 0x04) != 0:
            return self._install_for_install(
                payload,
                make_selectable=(sub_function & 0x08) != 0,
            )
        if (sub_function & 0x08) != 0:
            return self._install_for_make_selectable(payload)
        return b"", 0x6A, 0x86

    def handle_load(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        """GP Card Spec v2.3 §11.6 LOAD -- accumulates CAP/IJC block chunks and commits on last block."""
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

    # §11.2.2.2 Table 11-22: b8 deletes the object together with its related
    # objects, b7 (with b8 clear) a Security Domain and everything associated
    # with it, and b6 a Security Domain removing itself. b5..b1 are RFU.
    DELETE_P2_RELATED = 0x80
    DELETE_P2_SD_HIERARCHY = 0x40
    DELETE_P2_SELF_REMOVAL = 0x20
    DELETE_P2_RFU = 0x1F
    # §11.2.3.1 Table 11-25: the response always carries the length of the
    # delete confirmation; the simulator issues no Delegated Management
    # receipt, so the length is zero and no confirmation follows.
    DELETE_NO_CONFIRMATION = b"\x00"

    def handle_delete(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        """GPC v2.3.1 §11.2 DELETE -- remove an Application, Executable Load File or Security Domain.

        §11.2.2.1 Table 11-21 puts the segmentation flag in P1.b8; §11.2.2.2
        Table 11-22 selects what is deleted through P2; §11.2.3.1 Table 11-25
        makes a data field mandatory in the response.
        """
        p1_byte = int(p1) & 0xFF
        p2_byte = int(p2) & 0xFF
        if (p1_byte & 0x7F) != 0 or (p2_byte & self.DELETE_P2_RFU) != 0:
            self._delete_chain = b""
            return b"", 0x6A, 0x86

        payload = self._delete_chain + bytes(data or b"")
        if len(payload) > MAX_DELETE_CHAIN_BYTES:
            self._delete_chain = b""
            return b"", 0x6A, 0x80
        if (p1_byte & 0x80) != 0:
            # Segmented command data: hold the component and answer 90 00
            # until the last one arrives. The buffer is reset on every
            # dispatch and capped, so an unterminated chain cannot grow
            # without bound.
            self._delete_chain = payload
            return b"", 0x90, 0x00
        self._delete_chain = b""

        delete_related = (p2_byte & self.DELETE_P2_RELATED) != 0
        delete_hierarchy = (p2_byte & self.DELETE_P2_SD_HIERARCHY) != 0
        self_removal = (p2_byte & self.DELETE_P2_SELF_REMOVAL) != 0
        if len(payload) < 2 or payload[0] != 0x4F:
            return b"", 0x6A, 0x80
        aid_length = payload[1]
        if 2 + aid_length > len(payload):
            return b"", 0x6A, 0x80
        target_aid = payload[2 : 2 + aid_length].hex().upper()
        if len(target_aid) == 0:
            return b"", 0x6A, 0x82
        # §11.2.2.3 and §9.5.5: the Security Domain hierarchy and self-removal
        # forms name a Security Domain, which the simulator keeps outside the
        # application registry.
        if delete_hierarchy or self_removal:
            known_domains = {
                str(self.state.isdr_aid or "").upper(),
                str(self.state.ecasd_aid or "").upper(),
                str(self.state.mno_sd_aid or "").upper(),
            }
            if target_aid not in known_domains:
                return b"", 0x6A, 0x82
            # The simulator's domains are provisioned, not removable.
            return b"", 0x69, 0x85
        target_app = self._find_app(target_aid)
        if target_app is None:
            return b"", 0x6A, 0x82
        # §11.2.3.2: an Executable Load File that still has related
        # Applications cannot be deleted unless P2.b8 asks for them too.
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
        return self.DELETE_NO_CONFIRMATION, 0x90, 0x00

    def handle_put_key(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        """GP Card Spec v2.3 §11.8 PUT KEY -- stubs key-import (returns 9000 to satisfy INSTALL/PUT KEY sequences)."""
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
        """GP Card Spec v2.3 §11.9 SET STATUS -- transitions ISD or application life-cycle state."""
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
        # Table 11-42: L/Load File AID, L/Security Domain AID,
        # L/Load File Data Block Hash, BER-LV Load Parameters,
        # BER-LV Load Token.
        offset, elf_aid = self._take_lv(data, 0)
        if offset is None or len(elf_aid) == 0:
            return b"", 0x6A, 0x80
        offset, sd_aid = self._take_lv(data, offset)
        if offset is None:
            return b"", 0x6A, 0x80
        offset, _load_file_hash = self._take_lv(data, offset)
        if offset is None:
            return b"", 0x6A, 0x80
        offset, _load_parameters = self._take_ber_lv(data, offset)
        if offset is None:
            return b"", 0x6A, 0x80
        offset, _load_token = self._take_ber_lv(data, offset)
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
        # Table 11-43: L/Executable Load File AID, L/Executable Module
        # AID, L/Application AID, L/Privileges, BER-LV Install
        # Parameters, BER-LV Install Token.
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
        elif offset < len(data):
            # Install Parameters and Install Token carry BER lengths;
            # a truncated one is "incorrect values in command data".
            if self._take_ber_lv_pair(data, offset) is False:
                return b"", 0x6A, 0x80

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
        # Table 11-44: two '00' length fields, then L/Application AID,
        # L/Privileges, BER-LV Make Selectable Parameters, BER-LV Make
        # Selectable Token. The two leading empty fields keep the
        # command data field aligned with INSTALL [for install].
        offset, first_empty = self._take_lv(data, 0)
        if offset is None or len(first_empty) != 0:
            return b"", 0x6A, 0x80
        offset, second_empty = self._take_lv(data, offset)
        if offset is None or len(second_empty) != 0:
            return b"", 0x6A, 0x80
        offset, app_aid = self._take_lv(data, offset)
        if offset is None or len(app_aid) == 0:
            return b"", 0x6A, 0x80
        # §11.5.2.3.3: of the Privileges field only the Card Reset
        # privilege changes the registry; every other privilege is
        # ignored, so the stored privileges are left as INSTALL [for
        # install] recorded them.
        offset, privileges = self._take_lv(data, offset)
        if offset is None or len(privileges) not in (1, 3):
            return b"", 0x6A, 0x80
        if offset < len(data) and self._take_ber_lv_pair(data, offset) is False:
            return b"", 0x6A, 0x80

        target = self._find_app(app_aid.hex().upper())
        if target is None or target.kind != "application":
            return b"", 0x6A, 0x82
        target.lifecycle_state = GP_LCS_SELECTABLE
        return b"", 0x90, 0x00

    def _install_for_extradition(self, data: bytes) -> tuple[bytes, int, int]:
        # Table 11-45: L/Security Domain AID, '00', L/Application or
        # Executable Load File AID, '00', BER-LV Extradition
        # Parameters, BER-LV Extradition Token.
        offset, sd_aid = self._take_lv(data, 0)
        if offset is None or len(sd_aid) == 0:
            return b"", 0x6A, 0x80
        offset, first_empty = self._take_lv(data, offset)
        if offset is None or len(first_empty) != 0:
            return b"", 0x6A, 0x80
        offset, target_aid = self._take_lv(data, offset)
        if offset is None or len(target_aid) == 0:
            return b"", 0x6A, 0x80
        offset, second_empty = self._take_lv(data, offset)
        if offset is None or len(second_empty) != 0:
            return b"", 0x6A, 0x80
        if offset < len(data) and self._take_ber_lv_pair(data, offset) is False:
            return b"", 0x6A, 0x80

        if self._is_known_security_domain(sd_aid.hex().upper()) is False:
            return b"", 0x6A, 0x88
        target = self._find_app(target_aid.hex().upper())
        if target is None or target.kind not in ("application", "elf"):
            return b"", 0x6A, 0x82
        # The simulator runs a single Security Domain hierarchy, so the
        # extradition is accepted once both AIDs resolve; there is no
        # second SD to rebind the registry entry to.
        return b"", 0x90, 0x00

    def _install_for_personalization(self, data: bytes) -> tuple[bytes, int, int]:
        # Table 11-47: two '00' length fields, L/Application AID, then
        # three more '00' length fields. §11.5.2.3.6 hands the next
        # STORE DATA chain to the named Application; the SgpLogic
        # STORE DATA dispatcher does not key off the personalization
        # target, so the request is only validated here.
        offset = 0
        for _leading in range(2):
            offset, empty = self._take_lv(data, offset)
            if offset is None or len(empty) != 0:
                return b"", 0x6A, 0x80
        offset, app_aid = self._take_lv(data, offset)
        if offset is None or len(app_aid) == 0:
            return b"", 0x6A, 0x80
        if self._find_app(app_aid.hex().upper()) is None:
            return b"", 0x6A, 0x82
        return b"", 0x90, 0x00

    def _install_for_registry_update(self, data: bytes) -> tuple[bytes, int, int]:
        # Table 11-46: L/Security Domain AID (optional), '00',
        # L/Application AID (optional), L/Privileges ('00', '01' or
        # '03'), BER-LV Registry Update Parameters, BER-LV Registry
        # Update Token.
        offset, sd_aid = self._take_lv(data, 0)
        if offset is None:
            return b"", 0x6A, 0x80
        offset, first_empty = self._take_lv(data, offset)
        if offset is None or len(first_empty) != 0:
            return b"", 0x6A, 0x80
        offset, app_aid = self._take_lv(data, offset)
        if offset is None:
            return b"", 0x6A, 0x80
        offset, privileges = self._take_lv(data, offset)
        if offset is None:
            return b"", 0x6A, 0x80
        if len(privileges) not in (0, 1, 3):
            return b"", 0x6A, 0x80
        if offset < len(data) and self._take_ber_lv_pair(data, offset) is False:
            return b"", 0x6A, 0x80

        if len(sd_aid) > 0 and self._is_known_security_domain(sd_aid.hex().upper()) is False:
            return b"", 0x6A, 0x88
        if len(app_aid) == 0:
            # §11.5.2.3.5: the Application AID is absent only when the
            # request modifies the functionality of the OPEN, which the
            # simulator does not model.
            return b"", 0x90, 0x00
        target = self._find_app(app_aid.hex().upper())
        if target is None:
            return b"", 0x6A, 0x82
        if len(privileges) > 0:
            target.privileges = bytes(privileges)
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

    @staticmethod
    def _take_ber_lv(data: bytes, offset: int) -> tuple[int | None, bytes]:
        """BER-coded LV reader for the parameter and token fields.

        Tables 11-42 to 11-46 accept ``'00'-'80'``, ``'81 80'-'81 FF'``
        and ``'82 01 00'-'82 FF FF'``: a bare '80' is the literal
        length 128, not the indefinite-length indicator.
        """
        if offset >= len(data):
            return None, b""
        first = data[offset]
        start = offset + 1
        length = first
        if first == 0x81:
            if start + 1 > len(data):
                return None, b""
            length = data[start]
            start += 1
        elif first == 0x82:
            if start + 2 > len(data):
                return None, b""
            length = int.from_bytes(data[start : start + 2], "big")
            start += 2
        elif first > 0x82:
            return None, b""
        end = start + length
        if end > len(data):
            return None, b""
        return end, data[start:end]

    @classmethod
    def _take_ber_lv_pair(cls, data: bytes, offset: int) -> bool:
        """True when a parameters field and a token field parse cleanly from *offset*."""
        offset, _parameters = cls._take_ber_lv(data, offset)
        if offset is None:
            return False
        if offset >= len(data):
            return True
        offset, _token = cls._take_ber_lv(data, offset)
        return offset is not None

    def _is_known_security_domain(self, aid_hex: str) -> bool:
        """True when *aid_hex* names one of the card's Security Domains."""
        target = str(aid_hex or "").strip().upper()
        for sd_aid in (self.state.isdr_aid, self.state.ecasd_aid, self.state.mno_sd_aid):
            if str(sd_aid or "").strip().upper() == target:
                return True
        entry = self._find_app(target)
        return entry is not None and entry.kind == "sd"

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
        entries: list[tuple[str, bytes]],
        search_aid: bytes,
    ) -> tuple[bytes, int, int]:
        """Apply the §11.4.2.3 AID search criterion to built registry entries.

        The AID (tag '4F') is a prefix match so a search on a RID
        returns every occurrence sharing it; '4F' '00' matches all.
        """
        if len(search_aid) == 0:
            return b"".join(entry for _aid, entry in entries), 0x90, 0x00
        target_hex = search_aid.hex().upper()
        kept: list[bytes] = []
        for aid_hex, entry in entries:
            if aid_hex.startswith(target_hex):
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
        """Table 11-36 'E3' entry: AID, Life Cycle State and 3-byte Privileges.

        With no tag list in the command data field §11.4.3.1 requires
        exactly '4F', '9F70' and 'C5' for the Issuer Security Domain
        and for Applications, so 'C5' is emitted even when the registry
        holds no privileges. §11.5.2.3.2 has the OPEN extend one-byte
        privileges to three bytes.
        """
        body = tlv("4F", bytes.fromhex(aid_hex)) + tlv("9F70", bytes([life_cycle_state & 0xFF]))
        body += tlv("C5", bytes(privileges).ljust(3, b"\x00")[:3])
        return tlv("E3", body)

    @classmethod
    def _registry_entry(
        cls,
        aid_hex: str,
        life_cycle_state: int,
        privileges: bytes,
    ) -> tuple[str, bytes]:
        normalized = str(aid_hex or "").strip().upper()
        return normalized, cls._status_entry(normalized, life_cycle_state, privileges)

    @staticmethod
    def _load_file_entry(app: SimGpAppEntry, *, with_modules: bool) -> tuple[str, bytes]:
        """Table 11-37 'E3' entry for an Executable Load File.

        §11.4.3.1 pins the no-tag-list content to '4F', '9F70' and, per
        Note 2, the Executable Module AIDs under tag '84'. Privileges
        (tag 'C5') are an Application data object and are not part of
        an Executable Load File entry.
        """
        aid_hex = str(app.aid or "").strip().upper()
        body = tlv("4F", bytes.fromhex(aid_hex)) + tlv("9F70", bytes([app.lifecycle_state & 0xFF]))
        if with_modules:
            for module_aid in app.modules:
                normalized = str(module_aid or "").strip().upper()
                if len(normalized) == 0:
                    continue
                body += tlv("84", bytes.fromhex(normalized))
        return aid_hex, tlv("E3", body)
