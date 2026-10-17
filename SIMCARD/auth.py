# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""UICC authentication logic: Milenage KAT vectors, 5G AKA, and AuthLogic adapter (ETSI TS 135 206 / 3GPP TS 33.501)."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from SIMCARD.aka_5g import (
    derive_eap_aka_prime_keys,
    derive_k_ausf,
    derive_k_seaf,
    derive_res_star,
)
from SIMCARD.state import (
    MAX_HISTORY_ENTRIES,
    SimCardState,
    SimFileNode,
    SimGbaKeyMaterial,
    SimProfileAuthConfig,
)
from SIMCARD.tuak import (
    TuakVectors,
    derive_topc,
    tuak_f1,
    tuak_f2345,
    tuak_runtime_enabled,
    tuak_vectors,
)
from SIMCARD.utils import decode_impi_ef, read_tlv, tlv

_SQN_MAX = (1 << 48) - 1

# AUTHENTICATE with the even INS '88': P2 is '80' | context. TS 31.102 v19.5
# Table 7.1.2-1 (USIM): GSM '80', 3G/EPS/5G '81', VGCS/VBS '82', GBA '84'.
# TS 31.103 v19 §7.1.2 Table 1 (ISIM): '80' reserved, IMS AKA '81', HTTP
# Digest '82', GBA '84'. MBMS ('85') and Local Key Establishment ('86') are
# odd-INS ('89') contexts and RFU here.
P2_GSM_CONTEXT = 0x80
P2_AKA_CONTEXT = 0x81
P2_VGCS_OR_HTTP_DIGEST_CONTEXT = 0x82
P2_GBA_CONTEXT = 0x84

# TS 31.102 v19.5 §7.1.2.3 / §7.1.2.4, TS 31.103 v19 §7.1.2.3 / §7.1.2.4.
GBA_BOOTSTRAPPING_MODE_TAG = 0xDD
GBA_NAF_DERIVATION_MODE_TAG = 0xDE
GBA_SUCCESS_TAG = 0xDB
AKA_SYNCHRONISATION_FAILURE_TAG = 0xDC

# TS 33.220 v19.1 Annex B.3: P0 of Ks_ext_NAF and of Ks_int_NAF.
GBA_ME_KEY_LABEL = b"gba-me"
GBA_U_KEY_LABEL = b"gba-u"

ISIM_EF_IMPI_FID = "6F02"


@dataclass(frozen=True)
class GbaApplicationFiles:
    """Where one application keeps its GBA service bit and files."""

    service_table_fid: str
    service_number: int
    gbabp_fid: str
    gbanl_fid: str


# USIM: service n°68 in EF_UST '6F38' (TS 31.102 v19.5 §4.2.8, §7.1.1.4),
# EF_GBABP '6FD6' (§4.2.79), EF_GBANL '6FDA' (§4.2.83). ISIM: service n°2
# in EF_IST '6F07' (TS 31.103 v19 §4.2.7, §7.1.1.2), EF_GBABP '6FD5'
# (§4.2.9), EF_GBANL '6FD7' (§4.2.10).
GBA_APPLICATION_FILES: dict[str, GbaApplicationFiles] = {
    "ADF.USIM": GbaApplicationFiles("6F38", 68, "6FD6", "6FDA"),
    "ADF.ISIM": GbaApplicationFiles("6F07", 2, "6FD5", "6FD7"),
}


@dataclass(frozen=True)
class MilenageVectors:
    res: bytes
    ck: bytes
    ik: bytes
    kc: bytes
    sres: bytes
    ak: bytes
    ak_star: bytes
    mac_a: bytes
    mac_s: bytes


@dataclass(frozen=True)
class FiveGAuthVector:
    """ME-side 5G HE AV bundle produced from a USIM AUTHENTICATE.

    The USIM only returns the UMTS triple ``(res, ck, ik)``; the
    serving-network anchor keys are derived in the ME (or, for
    test-bench use, in :class:`AuthLogic`) per TS 33.501 Annex A.
    """

    res: bytes
    ck: bytes
    ik: bytes
    res_star: bytes
    k_ausf: bytes
    k_seaf: bytes
    ck_prime: bytes
    ik_prime: bytes
    sn_name: str
    sqn_xor_ak: bytes


def derive_opc(ki: bytes, op: bytes) -> bytes:
    """Compute OPc from Ki and OP (3GPP TS 33.102 Annex C.1).

    OPc = AES128_Ki(OP) XOR OP. Both arguments must be exactly 16 bytes.
    """
    key = bytes(ki or b"")
    operand = bytes(op or b"")
    if len(key) != 16 or len(operand) != 16:
        raise ValueError("Ki and OP must be 16 bytes each.")
    encrypted = _aes_ecb_encrypt(key, operand)
    return _xor_bytes(encrypted, operand)


def milenage_vectors(ki: bytes, opc: bytes, rand: bytes, sqn: bytes, amf: bytes) -> MilenageVectors:
    """Run the full Milenage f1-f5* function set (3GPP TS 33.102 Annex B).

    Returns all six MAC-A, MAC-S, RES, CK, IK, AK, AK* vectors plus the
    GSM-compatibility SRES and Kc conversions (Annex B.3/B.4).
    """
    key = bytes(ki or b"")
    operator_variant = bytes(opc or b"")
    challenge = bytes(rand or b"")
    sequence_number = bytes(sqn or b"")
    management_field = bytes(amf or b"")
    if len(key) != 16 or len(operator_variant) != 16 or len(challenge) != 16:
        raise ValueError("Milenage requires 16-byte Ki, OPc, and RAND values.")
    if len(sequence_number) != 6 or len(management_field) != 2:
        raise ValueError("Milenage requires a 6-byte SQN and 2-byte AMF.")

    temp = _aes_ecb_encrypt(key, _xor_bytes(challenge, operator_variant))
    in1 = sequence_number + management_field + sequence_number + management_field

    rijndael_input = _xor_bytes(_rotate_left_bytes(_xor_bytes(in1, operator_variant), 8), temp)
    out1 = _xor_bytes(_aes_ecb_encrypt(key, rijndael_input), operator_variant)
    mac_a = out1[:8]
    mac_s = out1[8:16]

    out2 = _xor_bytes(
        _aes_ecb_encrypt(
            key,
            _xor_bytes(_rotate_left_bytes(_xor_bytes(temp, operator_variant), 0), _constant_block(0x01)),
        ),
        operator_variant,
    )
    out3 = _xor_bytes(
        _aes_ecb_encrypt(
            key,
            _xor_bytes(_rotate_left_bytes(_xor_bytes(temp, operator_variant), 4), _constant_block(0x02)),
        ),
        operator_variant,
    )
    out4 = _xor_bytes(
        _aes_ecb_encrypt(
            key,
            _xor_bytes(_rotate_left_bytes(_xor_bytes(temp, operator_variant), 8), _constant_block(0x04)),
        ),
        operator_variant,
    )
    out5 = _xor_bytes(
        _aes_ecb_encrypt(
            key,
            _xor_bytes(_rotate_left_bytes(_xor_bytes(temp, operator_variant), 12), _constant_block(0x08)),
        ),
        operator_variant,
    )

    res = out2[8:16]
    ck = out3
    ik = out4
    ak = out2[:6]
    ak_star = out5[:6]
    # c2 conversion (TS 33.102 Annex B.3): SRES = RES[0..31] XOR RES[32..63]
    sres = _xor_bytes(res[:4], res[4:8])
    # c3 conversion (TS 33.102 Annex B.4): Kc = CK1 XOR CK2 XOR IK1 XOR IK2
    kc = _xor_bytes(_xor_bytes(ck[:8], ck[8:16]), _xor_bytes(ik[:8], ik[8:16]))
    return MilenageVectors(
        res=res,
        ck=ck,
        ik=ik,
        kc=kc,
        sres=sres,
        ak=ak,
        ak_star=ak_star,
        mac_a=mac_a,
        mac_s=mac_s,
    )


def build_milenage_autn(ki: bytes, opc: bytes, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
    vectors = milenage_vectors(ki, opc, rand, sqn, amf)
    concealed_sqn = _xor_bytes(bytes(sqn or b""), vectors.ak)
    return concealed_sqn + bytes(amf or b"") + vectors.mac_a


def build_milenage_auts(ki: bytes, opc: bytes, rand: bytes, sqn: bytes) -> bytes:
    """Build the AUTS token for sequence-number re-sync (3GPP TS 33.102 §6.3.3).

    AUTS = Conc(SQN_MS) || MAC-S, with AMF forced to zero per spec.
    """
    zero_amf = b"\x00\x00"
    vectors = milenage_vectors(ki, opc, rand, sqn, zero_amf)
    concealed_sqn = _xor_bytes(bytes(sqn or b""), vectors.ak_star)
    return concealed_sqn + vectors.mac_s


class AuthLogic:
    def __init__(self, state: SimCardState, file_system: object | None = None) -> None:
        self.state = state
        # Optional file-system handle so 5G AKA can persist KAUSF /
        # KSEAF into EF.5GAUTHKEYS (TS 31.102 §4.4.11.5). Kept as an
        # untyped attribute to avoid an import cycle with
        # ``SIMCARD.etsi_fs``; everything we call on it
        # (``write_ef_transparent_by_path``) is duck-typed.
        self.fs = file_system

    def reset(self) -> None:
        return

    def get_challenge(self, p1: int, p2: int, le: int | None) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.7 GET CHALLENGE.

        Returns ``Le`` random bytes; ``Le=0`` requests 256 bytes per
        ISO 7816-4 mapping. P1/P2 are reserved as ``00 00`` -- anything
        else is rejected with 6A 86 to mirror commercial UICC behaviour.
        The challenge is also persisted in
        ``state.last_challenge_bytes`` so STORE-DATA / OTA paths that
        feed it back as freshness can be exercised by tests.
        """
        if (int(p1) & 0xFF) != 0 or (int(p2) & 0xFF) != 0:
            return b"", 0x6A, 0x86
        if le is None:
            return b"", 0x67, 0x00
        normalized_le = int(le) & 0xFF
        challenge_length = 256 if normalized_le == 0 else normalized_le
        if challenge_length <= 0 or challenge_length > 256:
            return b"", 0x67, 0x00
        challenge = secrets.token_bytes(challenge_length)
        self.state.last_challenge_bytes = challenge
        return challenge, 0x90, 0x00

    def internal_authenticate(self, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        """AUTHENTICATE with the even INS '88', dispatched by its P2 context.

        The context coding belongs to the selected application (the P2
        constants above). With no USIM or ISIM selected the USIM table
        applies, so the GSM context stays reachable as before.
        """
        normalized_p2 = int(p2) & 0xFF
        application = self._selected_application_name()
        if normalized_p2 == P2_VGCS_OR_HTTP_DIGEST_CONTEXT:
            # VGCS/VBS (USIM) and HTTP Digest (ISIM) are not implemented:
            # TS 31.102 v19.5 §7.3.1 '98 64' security context not supported.
            return b"", 0x98, 0x64
        if normalized_p2 == P2_GBA_CONTEXT:
            return self._run_gba(application, payload)
        if normalized_p2 == P2_AKA_CONTEXT:
            # 3G/EPS/5G on the USIM, IMS AKA on the ISIM.
            return self._run_usim_authentication(payload)
        if normalized_p2 == P2_GSM_CONTEXT and application != "ADF.ISIM":
            return self._run_gsm_algorithm(payload)
        return b"", 0x6A, 0x86

    def derive_5g_vector(
        self,
        sn_name: str,
        rand: bytes,
        autn: bytes,
    ) -> FiveGAuthVector | None:
        """Run the full 5G HE-AV computation against the active profile.

        Implements TS 33.501 §6.1.3.2.0 from the USIM-plus-ME side:
        the simulator first runs the UMTS-shaped AUTHENTICATE
        (P2=0x81) internally, then derives the serving-network-bound
        anchor keys via :mod:`SIMCARD.aka_5g`. Returns ``None`` if
        the USIM rejects the input (sync failure, MAC mismatch,
        algorithm not supported); the caller is expected to handle
        the AUTS/RESYNC path through ``internal_authenticate``.
        """
        normalized_rand = bytes(rand or b"")
        normalized_autn = bytes(autn or b"")
        if len(normalized_rand) != 16 or len(normalized_autn) != 16:
            return None
        config = self._active_auth_config()
        if config is None:
            return None
        algorithm = str(config.algorithm or "").strip().lower()
        if algorithm not in ("milenage", "aka-milenage"):
            # 5G AKA tests target Milenage profiles; TUAK/EAP-AKA' on
            # TUAK is a separate work item.
            return None
        try:
            key, operator_variant = self._resolve_milenage_keys(config)
        except ValueError:
            return None
        amf = bytes(normalized_autn[6:8])
        initial = milenage_vectors(key, operator_variant, normalized_rand, b"\x00" * 6, amf)
        concealed_sqn = normalized_autn[:6]
        recovered_sqn = _xor_bytes(concealed_sqn, initial.ak)
        vectors = milenage_vectors(key, operator_variant, normalized_rand, recovered_sqn, amf)
        if hmac.compare_digest(vectors.mac_a, normalized_autn[8:16]) is False:
            return None
        sqn_xor_ak = bytes(concealed_sqn)
        res_star = derive_res_star(
            vectors.ck,
            vectors.ik,
            sn_name,
            normalized_rand,
            vectors.res,
        )
        k_ausf = derive_k_ausf(vectors.ck, vectors.ik, sn_name, sqn_xor_ak)
        k_seaf = derive_k_seaf(k_ausf, sn_name)
        ck_prime, ik_prime = derive_eap_aka_prime_keys(
            vectors.ck,
            vectors.ik,
            sn_name,
            sqn_xor_ak,
        )
        bundle = FiveGAuthVector(
            res=vectors.res,
            ck=vectors.ck,
            ik=vectors.ik,
            res_star=res_star,
            k_ausf=k_ausf,
            k_seaf=k_seaf,
            ck_prime=ck_prime,
            ik_prime=ik_prime,
            sn_name=str(sn_name),
            sqn_xor_ak=sqn_xor_ak,
        )
        self._persist_5g_authkeys(bundle)
        return bundle

    def _persist_5g_authkeys(self, bundle: "FiveGAuthVector") -> None:
        """Update EF.5GAUTHKEYS and EF.KAUSF-DERIVATION after a successful
        5G AKA so a subsequent ``READ BINARY`` against DF.5GS reflects
        the freshly-derived anchor keys.

        EF.5GAUTHKEYS layout (TS 31.102 §4.4.11.5):
            '80' Lk KAUSF || '81' Lk KSEAF
        EF.KAUSF-DERIVATION (4F16) is a 4-byte big-endian counter that
        the spec leaves operator-defined; we treat it as a monotonic
        derivation counter so a network audit can detect replay.
        """
        fs = self.fs
        if fs is None or hasattr(fs, "write_ef_transparent_by_path") is False:
            return

        def _ber_simple(tag: int, value: bytes) -> bytes:
            if len(value) <= 0x7F:
                return bytes((tag, len(value))) + bytes(value)
            length_bytes = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
            return bytes((tag, 0x80 | len(length_bytes))) + length_bytes + bytes(value)

        body = _ber_simple(0x80, bundle.k_ausf) + _ber_simple(0x81, bundle.k_seaf)
        fs.write_ef_transparent_by_path(
            ("MF", "ADF.USIM", "DF.5GS", "EF.5GAUTHKEYS"),
            body,
        )
        # Monotonic counter; clamp at 2**32 - 1 so the field stays
        # 4 bytes even after a long-running test session.
        existing_counter = self._read_ef_kausf_derivation_counter()
        next_counter = min(existing_counter + 1, 0xFFFFFFFF)
        fs.write_ef_transparent_by_path(
            ("MF", "ADF.USIM", "DF.5GS", "EF.KAUSF-DERIVATION"),
            next_counter.to_bytes(4, "big"),
        )

    def _read_ef_kausf_derivation_counter(self) -> int:
        fs = self.fs
        if fs is None or hasattr(fs, "find_node_by_path") is False:
            return 0
        node = fs.find_node_by_path(("MF", "ADF.USIM", "DF.5GS", "EF.KAUSF-DERIVATION"))
        if node is None:
            return 0
        raw = bytes(getattr(node, "data", b"") or b"")
        if len(raw) == 0:
            return 0
        return int.from_bytes(raw[:4].ljust(4, b"\x00"), "big")

    def _run_gsm_algorithm(self, payload: bytes) -> tuple[bytes, int, int]:
        config = self._active_auth_config()
        if config is None:
            return b"", 0x69, 0x85
        rand = bytes(payload or b"")
        if len(rand) != 16:
            return b"", 0x67, 0x00
        algorithm = str(config.algorithm or "").strip().lower()
        if algorithm == "tuak":
            if tuak_runtime_enabled() is False:
                return b"", 0x69, 0x85
            try:
                vectors = self._tuak_vectors_for_current_state(config, rand)
            except ValueError:
                return b"", 0x69, 0x85
            return _tuak_sres_kc(vectors), 0x90, 0x00
        try:
            vectors = self._milenage_vectors_for_current_state(config, rand)
        except ValueError:
            return b"", 0x69, 0x85
        return vectors.sres + vectors.kc, 0x90, 0x00

    def _run_usim_authentication(self, payload: bytes) -> tuple[bytes, int, int]:
        application = self._selected_application_name()
        if application not in ("ADF.USIM", "ADF.ISIM"):
            return b"", 0x69, 0x85
        # TS 31.102 v19.5 §7.1.2.1 case 1 ends with Kc; the ISIM's IMS AKA
        # answer (TS 31.103 v19 §7.1.2.1) stops at IK.
        with_kc = application == "ADF.USIM"
        config = self._active_auth_config()
        if config is None:
            return b"", 0x69, 0x85

        parsed = self._parse_usim_auth_payload(payload)
        if parsed is None:
            return b"", 0x67, 0x00
        rand, autn = parsed
        _, amf, mac_a = autn[:6], autn[6:8], autn[8:16]

        algorithm = str(config.algorithm or "").strip().lower()
        if algorithm == "tuak":
            if tuak_runtime_enabled() is False:
                return b"", 0x69, 0x85
            return self._run_usim_authentication_tuak(config, rand, autn, amf, mac_a, with_kc=with_kc)

        try:
            key, operator_variant = self._resolve_auth_keys(config)
        except ValueError:
            return b"", 0x69, 0x85
        # AK only depends on K, OPc, RAND (SQN is XOR-concealed), so the
        # derivation with SQN=0 yields the same AK as with the real SQN.
        initial_vectors = milenage_vectors(key, operator_variant, rand, b"\x00" * 6, amf)
        concealed_sqn = autn[:6]
        recovered_sqn = _xor_bytes(concealed_sqn, initial_vectors.ak)
        vectors = milenage_vectors(key, operator_variant, rand, recovered_sqn, amf)
        # Constant-time MAC check. The simulator itself is not a timing
        # oracle but every other MAC path in the codebase uses
        # ``hmac.compare_digest`` (see SIMCARD/scp03.py). Keep the
        # discipline uniform so a future move of this code into a
        # network-facing harness does not regress.
        if hmac.compare_digest(vectors.mac_a, mac_a) is False:
            return b"", 0x98, 0x62

        stored_sqn_bytes = bytes(config.sqn or b"\x00" * 6).rjust(6, b"\x00")[-6:]
        current_sqn = int.from_bytes(stored_sqn_bytes, "big")
        network_sqn_value = int.from_bytes(recovered_sqn, "big")
        if network_sqn_value < current_sqn:
            auts = build_milenage_auts(key, operator_variant, rand, stored_sqn_bytes)
            return b"\xDC\x0E" + auts, 0x90, 0x00

        config.sqn = self._bump_and_clamp_sqn(current_sqn, network_sqn_value)
        self._persist_active_profile()
        response = (
            b"\xDB\x08"
            + vectors.res
            + b"\x10"
            + vectors.ck
            + b"\x10"
            + vectors.ik
        )
        if with_kc:
            response += b"\x08" + vectors.kc
        return response, 0x90, 0x00

    def _run_usim_authentication_tuak(
        self,
        config: SimProfileAuthConfig,
        rand: bytes,
        autn: bytes,
        amf: bytes,
        mac_a: bytes,
        *,
        with_kc: bool = True,
    ) -> tuple[bytes, int, int]:
        try:
            key, operator_variant = self._resolve_auth_keys(config)
        except ValueError:
            return b"", 0x69, 0x85
        iterations = int(getattr(config, "number_of_keccak", 1) or 1)
        # TUAK f5 (AK) is derived from (K, RAND, TOPc) only; SQN and AMF are not
        # part of the Keccak input for f2345. A single tuak_f2345 call therefore
        # yields the correct AK without any probe state.
        try:
            _res, _ck, _ik, ak_vector = tuak_f2345(
                topc=operator_variant,
                rand=rand,
                key=key,
                number_of_keccak=iterations,
                res_size_bytes=8,
                ck_size_bytes=16,
                ik_size_bytes=16,
            )
        except ValueError:
            return b"", 0x69, 0x85
        concealed_sqn = autn[:6]
        recovered_sqn = _xor_bytes(concealed_sqn, ak_vector)
        try:
            computed_mac_a = tuak_f1(
                topc=operator_variant,
                rand=rand,
                sqn=recovered_sqn,
                amf=amf,
                key=key,
                number_of_keccak=iterations,
                mac_size_bytes=len(mac_a),
            )
        except ValueError:
            return b"", 0x69, 0x85
        if hmac.compare_digest(computed_mac_a, mac_a) is False:
            return b"", 0x98, 0x62
        stored_sqn_bytes = bytes(config.sqn or b"\x00" * 6).rjust(6, b"\x00")[-6:]
        current_sqn = int.from_bytes(stored_sqn_bytes, "big")
        network_sqn_value = int.from_bytes(recovered_sqn, "big")
        if network_sqn_value < current_sqn:
            return b"", 0x98, 0x62
        config.sqn = self._bump_and_clamp_sqn(current_sqn, network_sqn_value)
        self._persist_active_profile()
        # Build the TUAK response vector using the cached f2345 outputs.
        response = (
            b"\xDB"
            + bytes((len(_res) & 0xFF,))
            + _res
            + b"\x10"
            + _ck
            + b"\x10"
            + _ik
        )
        if with_kc:
            kc = _xor_bytes(_xor_bytes(_ck[:8], _ck[8:16]), _xor_bytes(_ik[:8], _ik[8:16]))
            response += b"\x08" + kc
        return response, 0x90, 0x00

    def _milenage_vectors_for_current_state(self, config: SimProfileAuthConfig, rand: bytes) -> MilenageVectors:
        key, operator_variant = self._resolve_auth_keys(config)
        sqn = bytes(config.sqn or b"\x00" * 6).rjust(6, b"\x00")[-6:]
        amf = bytes(config.amf or b"\x80\x00").rjust(2, b"\x00")[-2:]
        return milenage_vectors(key, operator_variant, rand, sqn, amf)

    def _tuak_vectors_for_current_state(self, config: SimProfileAuthConfig, rand: bytes) -> TuakVectors:
        key, topc = self._resolve_tuak_keys(config)
        sqn = bytes(config.sqn or b"\x00" * 6).rjust(6, b"\x00")[-6:]
        amf = bytes(config.amf or b"\x80\x00").rjust(2, b"\x00")[-2:]
        iterations = int(getattr(config, "number_of_keccak", 1) or 1)
        return tuak_vectors(
            topc=topc,
            rand=rand,
            sqn=sqn,
            amf=amf,
            key=key,
            number_of_keccak=iterations,
        )

    def _active_auth_config(self) -> SimProfileAuthConfig | None:
        profile = self._active_profile()
        if profile is None:
            return None
        config = getattr(profile, "auth_config", None)
        if isinstance(config, SimProfileAuthConfig):
            return config
        return None

    def _active_profile(self):
        active_aid = str(self.state.active_profile_aid or "").strip().upper()
        for profile in self.state.profiles:
            if str(profile.aid or "").strip().upper() == active_aid:
                return profile
        for profile in self.state.profiles:
            if str(profile.state or "").strip().lower() == "enabled":
                return profile
        return None

    def _resolve_auth_keys(self, config: SimProfileAuthConfig) -> tuple[bytes, bytes]:
        algorithm = str(config.algorithm or "").strip().lower()
        if algorithm in ("milenage", "aka-milenage"):
            return self._resolve_milenage_keys(config)
        if algorithm == "tuak":
            return self._resolve_tuak_keys(config)
        raise ValueError(f"Unsupported simulator auth algorithm: {algorithm or 'unset'}")

    def _resolve_milenage_keys(self, config: SimProfileAuthConfig) -> tuple[bytes, bytes]:
        key = bytes(config.ki or b"")
        operator_variant = bytes(config.opc or b"")
        if len(operator_variant) == 0 and len(bytes(config.op or b"")) == 16:
            operator_variant = derive_opc(key, bytes(config.op or b""))
            config.opc = operator_variant
        if len(key) != 16 or len(operator_variant) != 16:
            raise ValueError("Simulator auth profile requires 16-byte Ki and OPc/OP values.")
        return key, operator_variant

    def _resolve_tuak_keys(self, config: SimProfileAuthConfig) -> tuple[bytes, bytes]:
        key = bytes(config.ki or b"")
        operator_variant = bytes(config.opc or b"")
        operand = bytes(config.op or b"")
        if len(key) not in (16, 32):
            raise ValueError("TUAK key must be 128 or 256 bits.")
        if len(operator_variant) == 32:
            return key, operator_variant
        if len(operand) == 32:
            iterations = int(getattr(config, "number_of_keccak", 1) or 1)
            derived = derive_topc(operand, key, number_of_keccak=iterations)
            config.opc = derived
            return key, derived
        raise ValueError("TUAK profile requires a 32-byte TOPc (opc) or 32-byte TOP (op) value.")

    def _persist_active_profile(self) -> None:
        store_path = str(getattr(self.state, "profile_store_path", "") or "").strip()
        if len(store_path) == 0:
            return
        try:
            from SIMCARD.profile_store import sync_profiles_to_store
            sync_profiles_to_store(store_path, self.state.profiles)
        except Exception:
            return

    @staticmethod
    def _bump_and_clamp_sqn(current_sqn: int, network_sqn: int) -> bytes:
        # SQN is a 48-bit counter per TS 33.102 Annex C. Saturate at 2^48 - 1
        # to avoid to_bytes(6, "big") overflow when a test harness runs long.
        bumped = max(int(current_sqn), int(network_sqn)) + 1
        clamped = min(bumped, _SQN_MAX)
        return clamped.to_bytes(6, "big")

    def _selected_application_node(self) -> SimFileNode | None:
        node_id = str(self.state.current_node_id or "").strip()
        while len(node_id) > 0:
            node = self.state.nodes.get(node_id)
            if node is None:
                return None
            kind = str(getattr(node, "kind", "") or "").strip().lower()
            if kind == "adf":
                return node
            node_id = str(getattr(node, "parent_id", "") or "").strip()
        return None

    def _selected_application_name(self) -> str:
        node = self._selected_application_node()
        if node is None:
            return ""
        return str(getattr(node, "name", "") or "").strip().upper()

    def _application_ef(self, application: SimFileNode, fid: str) -> SimFileNode | None:
        """The EF with *fid* directly under *application*.

        Found by file ID: a profile-loaded tree names its nodes its own way.
        """
        for child_id in list(application.children):
            child = self.state.nodes.get(child_id)
            if child is not None and child.kind == "ef" and str(child.fid or "").upper() == fid:
                return child
        return None

    def _application_service_available(self, application: SimFileNode, files: GbaApplicationFiles) -> bool:
        table = self._application_ef(application, files.service_table_fid)
        if table is None:
            return False
        # One bit per service, service n°1 in b1 of byte 1 (TS 31.102 v19.5 §4.2.8).
        index, bit = divmod(files.service_number - 1, 8)
        data = bytes(table.data or b"")
        return index < len(data) and bool(data[index] & (1 << bit))

    @staticmethod
    def _parse_usim_auth_payload(payload: bytes) -> tuple[bytes, bytes] | None:
        normalized = bytes(payload or b"")
        if len(normalized) == 32:
            return normalized[:16], normalized[16:32]
        if len(normalized) != 34 or normalized[0] != 0x10 or normalized[17] != 0x10:
            return None
        return normalized[1:17], normalized[18:34]

    def _run_gba(self, application: str, payload: bytes) -> tuple[bytes, int, int]:
        """GBA context: the first data byte picks Bootstrapping ('DD') or NAF Derivation ('DE') Mode."""
        files = GBA_APPLICATION_FILES.get(application)
        node = self._selected_application_node()
        if files is None or node is None:
            return b"", 0x69, 0x85
        if self._application_service_available(node, files) is False:
            # TS 31.102 v19.5 §7.1.1.4 / TS 31.103 v19 §7.1.1.2: GBA only while
            # the service is available.
            return b"", 0x98, 0x64
        data = bytes(payload or b"")
        if len(data) == 0:
            return b"", 0x67, 0x00
        if data[0] == GBA_BOOTSTRAPPING_MODE_TAG:
            return self._run_gba_bootstrap(application, node, files, data[1:])
        if data[0] == GBA_NAF_DERIVATION_MODE_TAG:
            return self._run_gba_naf_derivation(application, node, files, data[1:])
        # '6A 80' is not among the AUTHENTICATE status words of TS 31.102 v19.5
        # §7.3.2: a mode the card does not know is a context it does not support.
        return b"", 0x98, 0x64

    def _run_gba_bootstrap(
        self,
        application: str,
        node: SimFileNode,
        files: GbaApplicationFiles,
        body: bytes,
    ) -> tuple[bytes, int, int]:
        """GBA_U Bootstrapping Mode (TS 31.102 v19.5 §7.1.1.4, TS 31.103 v19 §7.1.1.2).

        AUTN* carries MAC* = MAC xor Trunc(SHA-256(IK)), Trunc taking the
        first 64 bits (TS 33.220 v19.1 §5.3.2 step 4, §3.4). This card
        supports SHA-256, and such a card has no SHA-1 fallback (NOTE 2b). On
        success it keeps Ks = CK || IK with RAND, writes RAND to EF_GBABP and
        answers RES with its least significant bit flipped.
        """
        fields = _parse_length_prefixed_fields(body, 2)
        if fields is None or len(fields[0]) != 16 or len(fields[1]) != 16:
            return b"", 0x67, 0x00
        rand, autn_star = fields
        gbabp = self._application_ef(node, files.gbabp_fid)
        if gbabp is None or len(gbabp.data) < len(_ef_gbabp_after_bootstrap(rand, 0)):
            # No room for RAND: TS 31.102 v19.5 §7.3.1 '98 66'.
            return b"", 0x98, 0x66
        config = self._active_auth_config()
        if config is None:
            return b"", 0x69, 0x85
        algorithm = str(config.algorithm or "").strip().lower()
        if algorithm not in ("milenage", "aka-milenage"):
            # GBA is implemented over Milenage only; a TUAK profile is refused.
            return b"", 0x69, 0x85
        try:
            key, operator_variant = self._resolve_milenage_keys(config)
        except ValueError:
            return b"", 0x69, 0x85
        amf, mac_star = autn_star[6:8], autn_star[8:16]
        # AK and IK depend on K, OPc and RAND only.
        initial_vectors = milenage_vectors(key, operator_variant, rand, b"\x00" * 6, amf)
        mac_a = _xor_bytes(mac_star, hashlib.sha256(initial_vectors.ik).digest()[:8])
        recovered_sqn = _xor_bytes(autn_star[:6], initial_vectors.ak)
        vectors = milenage_vectors(key, operator_variant, rand, recovered_sqn, amf)
        if hmac.compare_digest(vectors.mac_a, mac_a) is False:
            return b"", 0x98, 0x62
        stored_sqn_bytes = bytes(config.sqn or b"\x00" * 6).rjust(6, b"\x00")[-6:]
        current_sqn = int.from_bytes(stored_sqn_bytes, "big")
        network_sqn_value = int.from_bytes(recovered_sqn, "big")
        if network_sqn_value < current_sqn:
            auts = build_milenage_auts(key, operator_variant, rand, stored_sqn_bytes)
            return bytes((AKA_SYNCHRONISATION_FAILURE_TAG, len(auts))) + auts, 0x90, 0x00
        config.sqn = self._bump_and_clamp_sqn(current_sqn, network_sqn_value)
        self._persist_active_profile()
        material = self.state.gba_key_material.setdefault(application, SimGbaKeyMaterial())
        material.ks = vectors.ck + vectors.ik
        material.rand = rand
        self._write_transparent(gbabp, _ef_gbabp_after_bootstrap(rand, len(gbabp.data)))
        res = _flip_last_bit(vectors.res)
        return bytes((GBA_SUCCESS_TAG, len(res))) + res, 0x90, 0x00

    def _run_gba_naf_derivation(
        self,
        application: str,
        node: SimFileNode,
        files: GbaApplicationFiles,
        body: bytes,
    ) -> tuple[bytes, int, int]:
        """GBA_U NAF Derivation Mode (TS 31.102 v19.5 §7.1.1.5, TS 31.103 v19 §7.1.1.3).

        The USIM takes NAF_ID and IMPI, the ISIM NAF_ID alone and IMPI from
        its EF_IMPI. Ks_ext_NAF goes back to the ME; Ks_int_NAF stays on the
        card with the B-TID, and EF_GBANL records the NAF_ID / B-TID pair.
        """
        with_impi = application != "ADF.ISIM"
        fields = _parse_length_prefixed_fields(body, 2 if with_impi else 1)
        if fields is None or any(len(value) == 0 for value in fields):
            return b"", 0x67, 0x00
        naf_id = fields[0]
        if with_impi:
            impi = fields[1]
        else:
            impi_ef = self._application_ef(node, ISIM_EF_IMPI_FID)
            if impi_ef is None:
                return b"", 0x69, 0x85
            try:
                impi = decode_impi_ef(impi_ef.data).encode("utf-8")
            except ValueError:
                return b"", 0x69, 0x85
        material = self.state.gba_key_material.get(application)
        if material is None or len(material.ks) == 0:
            # No bootstrapped key material: '69 85'.
            return b"", 0x69, 0x85
        gbabp = self._application_ef(node, files.gbabp_fid)
        b_tid = _ef_gbabp_b_tid(b"" if gbabp is None else gbabp.data, material.rand)
        record = tlv("80", naf_id) + tlv("81", b_tid)
        gbanl = self._application_ef(node, files.gbanl_fid)
        if gbanl is None or gbanl.structure != "linear-fixed":
            return b"", 0x98, 0x66
        record_number = _gbanl_target_record(gbanl.records, naf_id, material.naf_record_order)
        if record_number == 0 or len(record) > len(gbanl.records[record_number - 1]):
            # EF_GBANL cannot take the pair: TS 31.102 v19.5 §7.3.1 '98 66'.
            return b"", 0x98, 0x66
        ks_ext_naf = _gba_kdf(material.ks, GBA_ME_KEY_LABEL, material.rand, impi, naf_id)
        ks_int_naf = _gba_kdf(material.ks, GBA_U_KEY_LABEL, material.rand, impi, naf_id)
        self._write_record(gbanl, record_number, record)
        naf_key = naf_id.hex().upper()
        material.naf_keys.pop(naf_key, None)
        material.naf_keys[naf_key] = (ks_int_naf, b_tid)
        while len(material.naf_keys) > MAX_HISTORY_ENTRIES:
            material.naf_keys.pop(next(iter(material.naf_keys)))
        order = [record_number] + [number for number in material.naf_record_order if number != record_number]
        material.naf_record_order = order[: len(gbanl.records)]
        return bytes((GBA_SUCCESS_TAG, len(ks_ext_naf))) + ks_ext_naf, 0x90, 0x00

    def _write_transparent(self, node: SimFileNode, data: bytes) -> None:
        writer = getattr(self.fs, "write_ef_transparent_node", None)
        if writer is None:
            node.data = bytes(data)
            return
        writer(node, data)

    def _write_record(self, node: SimFileNode, record_number: int, record: bytes) -> None:
        writer = getattr(self.fs, "write_ef_record_node", None)
        if writer is None:
            length = len(node.records[record_number - 1])
            node.records[record_number - 1] = bytes(record) + b"\xFF" * (length - len(record))
            return
        writer(node, record_number, record)


def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(bytes(key)), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(bytes(block)) + encryptor.finalize()


def _constant_block(last_byte: int) -> bytes:
    return (b"\x00" * 15) + bytes((last_byte & 0xFF,))


def _rotate_left_bytes(value: bytes, byte_count: int) -> bytes:
    normalized = bytes(value or b"")
    if len(normalized) == 0:
        return b""
    offset = int(byte_count) % len(normalized)
    return normalized[offset:] + normalized[:offset]


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    left_bytes = bytes(left or b"")
    right_bytes = bytes(right or b"")
    if len(left_bytes) != len(right_bytes):
        raise ValueError("XOR inputs must have the same length.")
    return bytes(left_part ^ right_part for left_part, right_part in zip(left_bytes, right_bytes))


def _gba_kdf(ks: bytes, label: bytes, rand: bytes, impi: bytes, naf_id: bytes) -> bytes:
    """NAF key derivation of TS 33.220 v19.1 Annex B.2.0 / B.3.

    HMAC-SHA-256 keyed with Ks over S = FC || P0 || L0 || ... || P3 || L3,
    FC 0x01, P0 *label* ("gba-me" for Ks_ext_NAF, "gba-u" for Ks_int_NAF),
    P1 RAND, P2 IMPI, P3 NAF_ID, each L a two-byte length.
    """
    message = b"\x01"
    for parameter in (label, rand, impi, naf_id):
        value = bytes(parameter or b"")
        message += value + len(value).to_bytes(2, "big")
    return hmac.new(bytes(ks or b""), message, hashlib.sha256).digest()


def _parse_length_prefixed_fields(data: bytes, count: int) -> list[bytes] | None:
    """*count* fields, each a length byte and its value, filling *data* exactly.

    The GBA command data after its mode tag (TS 31.102 v19.5 §7.1.2.3 /
    §7.1.2.4, TS 31.103 v19 §7.1.2.3 / §7.1.2.4); None for any other shape.
    """
    raw = bytes(data or b"")
    fields: list[bytes] = []
    offset = 0
    for _ in range(count):
        if offset >= len(raw):
            return None
        end = offset + 1 + raw[offset]
        if end > len(raw):
            return None
        fields.append(raw[offset + 1 : end])
        offset = end
    if offset != len(raw):
        return None
    return fields


def _flip_last_bit(value: bytes) -> bytes:
    """*value* with its least significant bit inverted (TS 33.220 v19.1 §5.3.2 step 4)."""
    raw = bytes(value or b"")
    if len(raw) == 0:
        return raw
    return raw[:-1] + bytes((raw[-1] ^ 0x01,))


def _ef_gbabp_after_bootstrap(rand: bytes, file_size: int) -> bytes:
    """EF_GBABP once the card has bootstrapped (TS 31.102 v19.5 §4.2.79, §7.1.1.4).

    The RAND field is the card's to write; the B-TID and key lifetime fields
    stay empty for the ME, then 'FF' up to *file_size*.
    """
    content = bytes((len(rand),)) + bytes(rand) + b"\x00\x00"
    return content + b"\xFF" * max(0, int(file_size) - len(content))


def _ef_gbabp_b_tid(data: bytes, rand: bytes) -> bytes:
    """The B-TID EF_GBABP holds for the bootstrap that produced *rand* (TS 31.102 v19.5 §4.2.79).

    Empty when the file holds another RAND or none, or a field runs past it.
    """
    raw = bytes(data or b"")
    if len(raw) == 0:
        return b""
    rand_end = 1 + raw[0]
    if rand_end >= len(raw) or raw[1:rand_end] != bytes(rand or b""):
        return b""
    b_tid_end = rand_end + 1 + raw[rand_end]
    if b_tid_end > len(raw):
        return b""
    return raw[rand_end + 1 : b_tid_end]


def _gbanl_record_naf_id(record: bytes) -> bytes | None:
    """The NAF_ID of an EF_GBANL record ('80' TLV first, TS 31.102 v19.5 §4.2.83); None when unreadable."""
    try:
        tag, value, _raw_tlv, _next_offset = read_tlv(bytes(record or b""))
    except ValueError:
        return None
    if tag != b"\x80":
        return None
    return value


def _gbanl_target_record(records: list[bytes], naf_id: bytes, order: list[int]) -> int:
    """The EF_GBANL record a NAF_ID goes to (TS 31.102 v19.5 §7.1.1.5).

    The record already holding it, else the first free ('FF') one, else the
    one derived least recently; a record the card has not written since it
    started counts as older than any it has. 0 when the file has no records.
    """
    free = 0
    for number, record in enumerate(records, start=1):
        raw = bytes(record or b"")
        if len(raw) == 0 or raw[0] == 0xFF:
            if free == 0:
                free = number
            continue
        if _gbanl_record_naf_id(raw) == bytes(naf_id):
            return number
    if free != 0:
        return free
    known = [number for number in order if 1 <= number <= len(records)]
    for number in range(1, len(records) + 1):
        if number not in known:
            return number
    if len(known) > 0:
        return known[-1]
    return 0


def _tuak_kc(vectors: TuakVectors) -> bytes:
    ck = bytes(vectors.ck or b"")
    ik = bytes(vectors.ik or b"")
    if len(ck) < 16 or len(ik) < 16:
        return b"\x00" * 8
    return _xor_bytes(_xor_bytes(ck[:8], ck[8:16]), _xor_bytes(ik[:8], ik[8:16]))


def _tuak_sres_kc(vectors: TuakVectors) -> bytes:
    res = bytes(vectors.res or b"")
    # c2 conversion (TS 33.102 Annex B.3). When RES is 64 bits we XOR the two
    # halves; when RES is exactly 32 bits we use it directly; otherwise we fall
    # back to left-padded zero filling so the GSM tuple shape is preserved.
    if len(res) >= 8:
        sres = _xor_bytes(res[:4], res[4:8])
    elif len(res) == 4:
        sres = res
    else:
        sres = res.rjust(4, b"\x00")[:4]
    return sres + _tuak_kc(vectors)
