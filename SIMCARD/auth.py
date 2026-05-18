# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""UICC authentication logic: Milenage KAT vectors, 5G AKA, and AuthLogic adapter (ETSI TS 135 206 / 3GPP TS 33.501)."""
from __future__ import annotations

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
from SIMCARD.state import SimCardState, SimProfileAuthConfig
from SIMCARD.tuak import (
    TuakVectors,
    derive_topc,
    tuak_f1,
    tuak_f2345,
    tuak_runtime_enabled,
    tuak_vectors,
)

_SQN_MAX = (1 << 48) - 1


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
    """Run the full Milenage f1–f5* function set (3GPP TS 33.102 Annex B).

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
        """Dispatch INTERNAL AUTHENTICATE / AUTHENTICATE by algorithm (ETSI TS 102 221 §11.1.2).

        P2 selects the algorithm context: 0x80 GSM, 0x81 USIM AKA,
        0x82 IMS AKA, 0x88 VGCS, 0x89 GBA.
        """
        normalized_p2 = int(p2) & 0xFF
        if normalized_p2 == 0x80:
            return self._run_gsm_algorithm(payload)
        if normalized_p2 == 0x81:
            return self._run_usim_authentication(payload)
        if normalized_p2 == 0x82:
            # 3GPP TS 31.103 §7.1 IMS AKA. The ISIM application
            # implements AKA against the same Milenage parameters
            # as the USIM, but the AUTHENTICATE command is issued
            # under the ISIM context. The simulator routes this
            # through the regular UMTS AKA path because the
            # cryptographic chain is identical; only the calling
            # AID context differs at the dispatcher level.
            #
            # On a paired card the IMS AKA result is accepted by
            # the IMS (S-CSCF) authentication challenge in
            # SIP REGISTER, and the derived CK/IK are forwarded
            # to the IMS Authentication Server (AS).
            return self._run_usim_authentication(payload)
        if normalized_p2 == 0x84:
            # 3GPP TS 31.102 §7.1.2.1.2 GBA Bootstrap (P2=0x84). The
            # algorithm chain is identical to UMTS AKA; the only
            # difference is that on success the card caches Ks =
            # CK||IK and the freshness RAND for a later P2=0x85
            # NAF derivation.
            return self._run_gba_bootstrap(payload)
        if normalized_p2 == 0x85:
            # 3GPP TS 31.102 §7.1.2.1.3 GBA Security Context Mode
            # (P2=0x85). Inputs: NAF_Id and IMPI. Output: Ks_NAF
            # derived per TS 33.220 §B.0.
            return self._run_gba_naf_derivation(payload)
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
        if self._selected_application_name() not in ("ADF.USIM", "ADF.ISIM"):
            return b"", 0x69, 0x85
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
            return self._run_usim_authentication_tuak(config, rand, autn, amf, mac_a)

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
            + b"\x08"
            + vectors.kc
        )
        return response, 0x90, 0x00

    def _run_usim_authentication_tuak(
        self,
        config: SimProfileAuthConfig,
        rand: bytes,
        autn: bytes,
        amf: bytes,
        mac_a: bytes,
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
        kc = _xor_bytes(_xor_bytes(_ck[:8], _ck[8:16]), _xor_bytes(_ik[:8], _ik[8:16]))
        response = (
            b"\xDB"
            + bytes((len(_res) & 0xFF,))
            + _res
            + b"\x10"
            + _ck
            + b"\x10"
            + _ik
            + b"\x08"
            + kc
        )
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

    def _selected_application_name(self) -> str:
        node_id = str(self.state.current_node_id or "").strip()
        while len(node_id) > 0:
            node = self.state.nodes.get(node_id)
            if node is None:
                return ""
            name = str(getattr(node, "name", "") or "").strip().upper()
            kind = str(getattr(node, "kind", "") or "").strip().lower()
            if kind == "adf":
                return name
            node_id = str(getattr(node, "parent_id", "") or "").strip()
        return ""

    @staticmethod
    def _parse_usim_auth_payload(payload: bytes) -> tuple[bytes, bytes] | None:
        normalized = bytes(payload or b"")
        if len(normalized) == 32:
            return normalized[:16], normalized[16:32]
        if len(normalized) != 34 or normalized[0] != 0x10 or normalized[17] != 0x10:
            return None
        return normalized[1:17], normalized[18:34]

    def _run_gba_bootstrap(self, payload: bytes) -> tuple[bytes, int, int]:
        """3GPP TS 31.102 §7.1.2.1.2 / TS 33.220 §4.5 GBA Bootstrap.

        Reuses the regular UMTS AKA path so SQN tracking, AUTS sync
        recovery and MAC validation behave identically to a P2=0x81
        run. On success the card caches Ks = CK||IK plus the
        freshness RAND so a follow-on P2=0x85 NAF derivation can
        compute Ks_(ext)NAF without needing the network to replay
        the bootstrap input.
        """
        if self._selected_application_name() not in ("ADF.USIM", "ADF.ISIM"):
            return b"", 0x69, 0x85
        config = self._active_auth_config()
        if config is None:
            return b"", 0x69, 0x85
        algorithm = str(config.algorithm or "").strip().lower()
        if algorithm not in ("milenage", "aka-milenage"):
            # TS 33.220 only mandates Milenage for GBA. TUAK is
            # allowed but not yet wired to the GBA cache; keep the
            # rejection explicit so a future test enables it.
            return b"", 0x69, 0x85
        parsed = self._parse_usim_auth_payload(payload)
        if parsed is None:
            return b"", 0x67, 0x00
        rand, autn = parsed
        amf, mac_a = autn[6:8], autn[8:16]
        try:
            key, operator_variant = self._resolve_milenage_keys(config)
        except ValueError:
            return b"", 0x69, 0x85
        initial_vectors = milenage_vectors(key, operator_variant, rand, b"\x00" * 6, amf)
        concealed_sqn = autn[:6]
        recovered_sqn = _xor_bytes(concealed_sqn, initial_vectors.ak)
        vectors = milenage_vectors(key, operator_variant, rand, recovered_sqn, amf)
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
        # Cache the bootstrap context. The simulator picks a B-TID
        # of the form ``<rand-hex>@bsf.simulator`` so a downstream
        # NAF lookup can reproduce the value without the BSF having
        # actually replied -- real deployments take the B-TID from
        # the BSF over Ub. ``gba_key_lifetime`` is the spec-default
        # 86400 s window per TS 33.220 §4.4.6.
        self.state.gba_ks = vectors.ck + vectors.ik
        self.state.gba_b_tid = f"{rand.hex()}@bsf.simulator"
        self.state.gba_key_lifetime = 86400
        self.state.last_challenge_bytes = rand
        response = (
            b"\xDB\x08"
            + vectors.res
            + b"\x10"
            + vectors.ck
            + b"\x10"
            + vectors.ik
        )
        return response, 0x90, 0x00

    def _run_gba_naf_derivation(self, payload: bytes) -> tuple[bytes, int, int]:
        """3GPP TS 31.102 §7.1.2.1.3 / TS 33.220 §B.0 NAF derivation.

        Input layout: ``L_NAF || NAF_Id || L_IMPI || IMPI``. The
        function rejects the request with ``69 85`` when no Ks is
        cached (no prior bootstrap) and ``67 00`` when the input
        TLV layout is malformed. Successful runs derive Ks_(ext)NAF
        per TS 33.220 §B.0 using HMAC-SHA-256 with the static
        ``"gba-me"`` salt and return ``DB 20 || Ks_NAF`` so a
        modem-side ME library can splice it into the standard AKA
        response framing.
        """
        if self._selected_application_name() not in ("ADF.USIM", "ADF.ISIM"):
            return b"", 0x69, 0x85
        if len(self.state.gba_ks) != 32:
            return b"", 0x69, 0x85
        normalized = bytes(payload or b"")
        if len(normalized) < 2:
            return b"", 0x67, 0x00
        naf_length = int(normalized[0])
        if naf_length == 0 or naf_length + 2 > len(normalized):
            return b"", 0x67, 0x00
        naf_id = normalized[1 : 1 + naf_length]
        impi_offset = 1 + naf_length
        impi_length = int(normalized[impi_offset])
        if impi_length == 0 or impi_offset + 1 + impi_length > len(normalized):
            return b"", 0x67, 0x00
        impi = normalized[impi_offset + 1 : impi_offset + 1 + impi_length]
        rand = bytes(self.state.last_challenge_bytes or b"")
        if len(rand) != 16:
            return b"", 0x69, 0x85
        ks_naf = _gba_kdf(self.state.gba_ks, rand, impi, naf_id)
        record_key = (naf_id + b"|" + impi).hex()
        self.state.gba_naf_records[record_key] = ks_naf
        return b"\xDB\x20" + ks_naf, 0x90, 0x00


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


def _gba_kdf(ks: bytes, rand: bytes, impi: bytes, naf_id: bytes) -> bytes:
    """3GPP TS 33.220 §B.0 GBA key derivation (Ks_(ext)NAF).

    Builds the standard FC=0x01 input string for the generic 3GPP
    KDF and runs HMAC-SHA-256 keyed with Ks. The FC value 0x01 is
    the "GBA Bootstrapping" specifier; the static prefix
    ``"gba-me"`` (six ASCII bytes) appears as P0 per Annex B.0 and
    fixes the derivation to the ME variant of the NAF key.
    """
    import hashlib

    p0 = b"gba-me"
    p1 = bytes(rand or b"")
    p2 = bytes(impi or b"")
    p3 = bytes(naf_id or b"")
    payload = b""
    payload += b"\x01"
    payload += p0 + len(p0).to_bytes(2, "big")
    payload += p1 + len(p1).to_bytes(2, "big")
    payload += p2 + len(p2).to_bytes(2, "big")
    payload += p3 + len(p3).to_bytes(2, "big")
    return hmac.new(bytes(ks or b""), payload, hashlib.sha256).digest()


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
