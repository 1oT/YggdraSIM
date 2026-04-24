from __future__ import annotations

import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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


def derive_opc(ki: bytes, op: bytes) -> bytes:
    key = bytes(ki or b"")
    operand = bytes(op or b"")
    if len(key) != 16 or len(operand) != 16:
        raise ValueError("Ki and OP must be 16 bytes each.")
    encrypted = _aes_ecb_encrypt(key, operand)
    return _xor_bytes(encrypted, operand)


def milenage_vectors(ki: bytes, opc: bytes, rand: bytes, sqn: bytes, amf: bytes) -> MilenageVectors:
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
    zero_amf = b"\x00\x00"
    vectors = milenage_vectors(ki, opc, rand, sqn, zero_amf)
    concealed_sqn = _xor_bytes(bytes(sqn or b""), vectors.ak_star)
    return concealed_sqn + vectors.mac_s


class AuthLogic:
    def __init__(self, state: SimCardState) -> None:
        self.state = state

    def reset(self) -> None:
        return

    def internal_authenticate(self, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        normalized_p2 = int(p2) & 0xFF
        if normalized_p2 == 0x80:
            return self._run_gsm_algorithm(payload)
        if normalized_p2 == 0x81:
            return self._run_usim_authentication(payload)
        return b"", 0x6A, 0x86

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
