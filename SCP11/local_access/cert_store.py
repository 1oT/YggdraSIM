import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID


@dataclass(frozen=True)
class CiCertificateRecord:
    variant_group: str
    variant_name: str
    curve: str
    path: str
    subject: str
    issuer: str
    ski: str
    der_bytes: bytes


@dataclass(frozen=True)
class SmdpCertificateRecord:
    role: str
    source: str
    variant_group: str
    variant_name: str
    curve: str
    certificate_path: str
    private_key_path: str
    subject: str
    issuer: str
    ski: str
    aki: str
    root_ci_ski: str
    der_bytes: bytes
    private_key: Any
    server_address: str


class LocalSgp26CertStore:
    """Preloads valid SGP.26 certificates and local drop-ins for local use."""

    CERTIFICATE_EXTENSIONS: tuple[str, ...] = (".der", ".pem", ".crt", ".cer")

    def __init__(
        self,
        valid_cert_root: str,
        prefer_curve: str = "NIST",
        override_cert_root: str = "",
        default_server_address: str = "",
        default_root_ci_id: str = "",
    ):
        self.valid_cert_root = str(valid_cert_root)
        self.prefer_curve = str(prefer_curve).strip().upper() or "NIST"
        self.override_cert_root = str(override_cert_root or "").strip()
        self.default_server_address = str(default_server_address or "").strip()
        self.default_root_ci_id = str(default_root_ci_id or "").strip().upper()
        self._loaded = False
        self._ci_records: list[CiCertificateRecord] = []
        self._subca_by_ski: dict[str, str] = {}
        self._auth_records: list[SmdpCertificateRecord] = []
        self._pb_records: list[SmdpCertificateRecord] = []

    def load(self) -> None:
        if self._loaded:
            return

        self._ci_records = []
        self._subca_by_ski = {}
        self._auth_records = []
        self._pb_records = []

        if os.path.isdir(self.valid_cert_root):
            self._ci_records = self._load_ci_records()
            self._subca_by_ski = self._load_subca_root_map()
            self._auth_records.extend(self._load_smdp_records(role="auth"))
            self._pb_records.extend(self._load_smdp_records(role="pb"))

        self._auth_records.extend(self._load_override_smdp_records(role="auth"))
        self._pb_records.extend(self._load_override_smdp_records(role="pb"))
        self._loaded = True

    def ci_records(self) -> list[CiCertificateRecord]:
        self.load()
        return list(self._ci_records)

    def auth_records(self) -> list[SmdpCertificateRecord]:
        self.load()
        return list(self._auth_records)

    def pb_records(self) -> list[SmdpCertificateRecord]:
        self.load()
        return list(self._pb_records)

    def has_local_override_records(self) -> bool:
        self.load()
        for record in self._auth_records + self._pb_records:
            if record.source == "local_override":
                return True
        return False

    def resolve_auth_record(self, allowed_ci_pkids: list[str]) -> Optional[SmdpCertificateRecord]:
        self.load()
        return self._resolve_record(self._auth_records, allowed_ci_pkids)

    def resolve_pb_record(self, allowed_ci_pkids: list[str]) -> Optional[SmdpCertificateRecord]:
        self.load()
        return self._resolve_record(self._pb_records, allowed_ci_pkids)

    def _resolve_record(
        self,
        records: list[SmdpCertificateRecord],
        allowed_ci_pkids: list[str],
    ) -> Optional[SmdpCertificateRecord]:
        normalized_allowed = [value.strip().upper() for value in allowed_ci_pkids if len(value.strip()) > 0]
        candidates = list(records)
        if len(normalized_allowed) > 0:
            allowed_matches = [record for record in candidates if record.root_ci_ski in normalized_allowed]
            if len(allowed_matches) > 0:
                candidates = allowed_matches
        if len(candidates) == 0:
            return None

        preferred_curve = self.prefer_curve
        curve_candidates = [record for record in candidates if record.curve == preferred_curve]
        if len(curve_candidates) > 0:
            candidates = curve_candidates

        candidates.sort(
            key=lambda record: (
                self._record_preference_rank(record),
                0 if len(record.aki) > 0 and record.aki == record.root_ci_ski else 1,
                record.variant_group,
                record.variant_name,
                record.role,
                record.curve,
                record.certificate_path,
            )
        )
        return candidates[0]

    @staticmethod
    def _record_preference_rank(record: SmdpCertificateRecord) -> tuple[int, int]:
        basename = os.path.basename(record.certificate_path).upper()
        source_rank = 0 if record.source == "local_override" else 1
        dp2_rank = 1 if "_DP2AUTH_" in basename or "_DP2PB_" in basename else 0
        return (source_rank, dp2_rank)

    def _load_ci_records(self) -> list[CiCertificateRecord]:
        records: list[CiCertificateRecord] = []
        for cert_path in self._iter_paths("**/CI/CERT_CI_SIG_*.pem"):
            certificate = self._load_certificate(cert_path)
            records.append(
                CiCertificateRecord(
                    variant_group=self._variant_group(cert_path),
                    variant_name=self._variant_name(cert_path),
                    curve=self._curve_name(cert_path, certificate),
                    path=cert_path,
                    subject=certificate.subject.rfc4514_string(),
                    issuer=certificate.issuer.rfc4514_string(),
                    ski=self._subject_key_identifier(certificate),
                    der_bytes=certificate.public_bytes(serialization.Encoding.DER),
                )
            )
        return records

    def _load_subca_root_map(self) -> dict[str, str]:
        output: dict[str, str] = {}
        for cert_path in self._iter_paths("**/SM-DP+/SM_DPSubCA/CERT_*.pem"):
            certificate = self._load_certificate(cert_path)
            subca_ski = self._subject_key_identifier(certificate)
            root_aki = self._authority_key_identifier(certificate)
            if len(subca_ski) == 0:
                continue
            if len(root_aki) == 0:
                continue
            output[subca_ski] = root_aki
        return output

    def _load_smdp_records(self, role: str) -> list[SmdpCertificateRecord]:
        if role == "auth":
            pattern = "**/SM-DP+/SM_DPauth/CERT_*.der"
        elif role == "pb":
            pattern = "**/SM-DP+/SM_DPpb/CERT_*.der"
        else:
            raise ValueError(f"Unsupported SM-DP+ role: {role}")

        records: list[SmdpCertificateRecord] = []
        for cert_path in self._iter_paths(pattern):
            private_key_path = self._matching_private_key_path(cert_path)
            if len(private_key_path) == 0 or os.path.exists(private_key_path) is False:
                continue

            certificate = self._load_certificate(cert_path)
            private_key = self._load_private_key(private_key_path)
            aki = self._authority_key_identifier(certificate)
            root_ci_ski = aki
            if aki in self._subca_by_ski:
                root_ci_ski = self._subca_by_ski[aki]

            records.append(
                SmdpCertificateRecord(
                    role=role,
                    source="sgp26_bundle",
                    variant_group=self._variant_group(cert_path),
                    variant_name=self._variant_name(cert_path),
                    curve=self._curve_name(cert_path, certificate),
                    certificate_path=cert_path,
                    private_key_path=private_key_path,
                    subject=certificate.subject.rfc4514_string(),
                    issuer=certificate.issuer.rfc4514_string(),
                    ski=self._subject_key_identifier(certificate),
                    aki=aki,
                    root_ci_ski=root_ci_ski,
                    der_bytes=certificate.public_bytes(serialization.Encoding.DER),
                    private_key=private_key,
                    server_address="",
                )
            )
        return records

    def _load_override_smdp_records(self, role: str) -> list[SmdpCertificateRecord]:
        root = str(self.override_cert_root).strip()
        if len(root) == 0 or os.path.isdir(root) is False:
            return []
        records: list[SmdpCertificateRecord] = []
        for path in sorted(Path(root).rglob("*")):
            if path.is_file() is False:
                continue
            if path.suffix.lower() not in self.CERTIFICATE_EXTENSIONS:
                continue
            basename = path.name.lower()
            if basename == "readme.md" or basename.endswith(".meta.json"):
                continue
            metadata = self._load_sidecar_metadata(str(path))
            record_role = self._override_record_role(str(path), metadata)
            if record_role != role:
                continue
            private_key_path = self._matching_override_private_key_path(str(path), metadata)
            if len(private_key_path) == 0 or os.path.exists(private_key_path) is False:
                continue
            try:
                certificate = self._load_certificate(str(path))
                private_key = self._load_private_key(private_key_path)
            except Exception:
                continue
            aki = self._authority_key_identifier(certificate)
            root_ci_ski = self._override_root_ci_ski(aki, metadata)
            records.append(
                SmdpCertificateRecord(
                    role=role,
                    source="local_override",
                    variant_group="Local Override",
                    variant_name="Local Override",
                    curve=self._curve_name(str(path), certificate),
                    certificate_path=str(path.resolve()),
                    private_key_path=str(Path(private_key_path).resolve()),
                    subject=certificate.subject.rfc4514_string(),
                    issuer=certificate.issuer.rfc4514_string(),
                    ski=self._subject_key_identifier(certificate),
                    aki=aki,
                    root_ci_ski=root_ci_ski,
                    der_bytes=certificate.public_bytes(serialization.Encoding.DER),
                    private_key=private_key,
                    server_address=self._override_server_address(metadata),
                )
            )
        return records

    def _iter_paths(self, pattern: str) -> list[str]:
        root = Path(self.valid_cert_root)
        return [str(path) for path in sorted(root.glob(pattern)) if path.is_file()]

    def _matching_private_key_path(self, certificate_path: str) -> str:
        directory = os.path.dirname(certificate_path)
        filename = os.path.basename(certificate_path)
        stem, _ = os.path.splitext(filename)
        match = re.match(r"^CERT_(.+?)_VAR[^_]+_(SIG_.+)$", stem)
        if match is None:
            return ""
        key_name = f"SK_{match.group(1)}_{match.group(2)}.pem"
        return os.path.join(directory, key_name)

    def _matching_override_private_key_path(self, certificate_path: str, metadata: dict[str, Any]) -> str:
        explicit = str(metadata.get("private_key_path", "")).strip()
        if len(explicit) > 0:
            if os.path.isabs(explicit):
                return explicit
            return os.path.join(os.path.dirname(certificate_path), explicit)
        directory = os.path.dirname(certificate_path)
        stem = os.path.splitext(os.path.basename(certificate_path))[0]
        guesses: list[str] = []
        if stem.startswith("CERT."):
            guesses.append(os.path.join(directory, f"SK.{stem[5:]}.pem"))
        if stem.startswith("CERT_"):
            guesses.append(os.path.join(directory, f"SK_{stem[5:]}.pem"))
        guesses.append(os.path.join(directory, f"{stem}.key.pem"))
        for guess in guesses:
            if os.path.isfile(guess):
                return guess
        return ""

    def _override_record_role(self, certificate_path: str, metadata: dict[str, Any]) -> str:
        role = str(metadata.get("role", "")).strip().lower()
        if role in ("auth", "pb"):
            return role
        basename = os.path.basename(certificate_path).upper()
        if "DPAUTH" in basename or "SM_DPAUTH" in basename:
            return "auth"
        if "DPPB" in basename or "SM_DPPB" in basename:
            return "pb"
        if basename == "CERT.DPAUTH.ECDSA.DER":
            return "auth"
        if basename == "CERT.DPPB.ECDSA.DER":
            return "pb"
        return ""

    def _override_root_ci_ski(self, aki: str, metadata: dict[str, Any]) -> str:
        metadata_value = self._normalize_ci_pkid(metadata.get("root_ci_pkid", ""))
        if len(metadata_value) > 0:
            return metadata_value
        if len(aki) > 0:
            if aki in self._subca_by_ski:
                return self._subca_by_ski[aki]
            return aki
        return self.default_root_ci_id

    def _override_server_address(self, metadata: dict[str, Any]) -> str:
        for key in ("server_address", "smdp_address"):
            candidate = str(metadata.get(key, "")).strip()
            if len(candidate) > 0:
                return candidate
        return self.default_server_address

    @staticmethod
    def _load_sidecar_metadata(certificate_path: str) -> dict[str, Any]:
        candidates = [
            f"{certificate_path}.meta.json",
            os.path.splitext(certificate_path)[0] + ".meta.json",
        ]
        for candidate in candidates:
            if os.path.isfile(candidate) is False:
                continue
            try:
                with open(candidate, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception:
                continue
            if isinstance(payload, dict):
                return payload
        return {}

    @staticmethod
    def _variant_group(path: str) -> str:
        normalized = path.replace("\\", "/")
        if "/Valid Test Cases/" in normalized:
            normalized = normalized.split("/Valid Test Cases/", 1)[1]
        parts = normalized.split("/")
        if len(parts) == 0:
            return ""
        return parts[0]

    @staticmethod
    def _variant_name(path: str) -> str:
        normalized = path.replace("\\", "/")
        if "/Valid Test Cases/" in normalized:
            normalized = normalized.split("/Valid Test Cases/", 1)[1]
        parts = normalized.split("/")
        for part in parts:
            if part.startswith("Variant "):
                return part
        if len(parts) > 0:
            return parts[0]
        return ""

    @staticmethod
    def _curve_name(path: str, certificate: Optional[crypto_x509.Certificate] = None) -> str:
        upper_path = path.upper()
        if "_NIST" in upper_path:
            return "NIST"
        if "_BRP" in upper_path:
            return "BRP"
        if certificate is not None:
            public_key = certificate.public_key()
            curve = getattr(public_key, "curve", None)
            curve_name = str(getattr(curve, "name", "") or "").strip().lower()
            if curve_name in ("secp256r1", "prime256v1"):
                return "NIST"
            if curve_name == "brainpoolp256r1":
                return "BRP"
        return ""

    @staticmethod
    def _load_certificate(path: str) -> crypto_x509.Certificate:
        with open(path, "rb") as cert_file:
            cert_data = cert_file.read()
        if path.lower().endswith(".pem"):
            return crypto_x509.load_pem_x509_certificate(cert_data)
        return crypto_x509.load_der_x509_certificate(cert_data)

    @staticmethod
    def _load_private_key(path: str) -> Any:
        with open(path, "rb") as key_file:
            key_data = key_file.read()
        return serialization.load_pem_private_key(key_data, password=None)

    @staticmethod
    def _subject_key_identifier(certificate: crypto_x509.Certificate) -> str:
        try:
            extension = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        except Exception:
            return ""
        return extension.value.digest.hex().upper()

    @staticmethod
    def _authority_key_identifier(certificate: crypto_x509.Certificate) -> str:
        try:
            extension = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        except Exception:
            return ""
        key_identifier = extension.value.key_identifier
        if key_identifier is None:
            return ""
        return key_identifier.hex().upper()

    @staticmethod
    def _normalize_ci_pkid(value: Any) -> str:
        text = str(value or "").strip().replace(" ", "").upper()
        if len(text) == 0:
            return ""
        if len(text) % 2 != 0:
            return ""
        try:
            bytes.fromhex(text)
        except ValueError:
            return ""
        return text
