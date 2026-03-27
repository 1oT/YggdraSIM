import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass(frozen=True)
class EimCertificateRecord:
    role: str
    source: str
    certificate_path: str
    private_key_path: str
    subject: str
    issuer: str
    subject_cn: str
    curve: str
    ski: str
    aki: str
    root_ci_pkids: tuple[str, ...]
    der_bytes: bytes


class EimCertificateStore:
    """Inventory and ranking helper for eIM certificate selection."""

    CERTIFICATE_EXTENSIONS: tuple[str, ...] = (".der", ".pem", ".crt", ".cer")

    def __init__(
        self,
        *,
        local_cert_root: str,
        sgp26_valid_cert_root: str = "",
        prefer_curve: str = "NIST",
        identity_default_cert_path: str = "",
        identity_default_ci_pkid: str = "",
    ) -> None:
        self.local_cert_root = os.path.abspath(str(local_cert_root or "").strip())
        self.sgp26_valid_cert_root = os.path.abspath(str(sgp26_valid_cert_root or "").strip())
        self.prefer_curve = str(prefer_curve or "").strip().upper() or "NIST"
        self.identity_default_cert_path = self._normalize_path(identity_default_cert_path)
        self.identity_default_ci_pkid = self._normalize_ci_pkid(identity_default_ci_pkid)
        self._loaded = False
        self._records: list[EimCertificateRecord] = []
        self._record_by_path: dict[str, EimCertificateRecord] = {}

    def load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        self._records = []
        self._record_by_path = {}
        for source, root in self._scan_roots():
            for certificate_path in self._iter_certificate_paths(root):
                record = self._load_record(certificate_path, source)
                if record is None:
                    continue
                normalized_path = self._normalize_path(record.certificate_path)
                if len(normalized_path) == 0:
                    continue
                if normalized_path in self._record_by_path:
                    continue
                self._records.append(record)
                self._record_by_path[normalized_path] = record

    def signing_records(self) -> list[EimCertificateRecord]:
        self.load()
        return [record for record in self._records if record.role == "signing"]

    def record_for_path(self, path_text: str) -> Optional[EimCertificateRecord]:
        self.load()
        normalized = self._normalize_path(path_text)
        if len(normalized) == 0:
            return None
        record = self._record_by_path.get(normalized)
        if record is not None:
            return record
        return self._load_record(normalized, source=self._source_for_path(normalized))

    def resolve_signing_record(
        self,
        *,
        allowed_ci_pkids: list[str],
        preferred_ci_pkids: list[str],
        fallback_path: str = "",
    ) -> Optional[EimCertificateRecord]:
        self.load()
        allowed = self._normalize_ci_pkid_list(allowed_ci_pkids)
        preferred = self._normalize_ci_pkid_list(preferred_ci_pkids)
        fallback_normalized = self._normalize_path(fallback_path)
        records = self.signing_records()
        fallback_record = self.record_for_path(fallback_normalized)
        if fallback_record is not None and fallback_record.role == "signing":
            if fallback_record.certificate_path not in {record.certificate_path for record in records}:
                records.append(fallback_record)
        if len(records) == 0:
            return None
        candidates = list(records)
        if len(allowed) > 0:
            allowed_matches = [
                record for record in candidates
                if len(set(record.root_ci_pkids).intersection(allowed)) > 0
            ]
            if len(allowed_matches) > 0:
                candidates = allowed_matches
        if len(preferred) > 0:
            preferred_matches = [
                record for record in candidates
                if len(set(record.root_ci_pkids).intersection(preferred)) > 0
            ]
            if len(preferred_matches) > 0:
                candidates = preferred_matches
        candidates.sort(
            key=lambda record: self._record_sort_key(
                record=record,
                allowed_ci_pkids=allowed,
                preferred_ci_pkids=preferred,
                fallback_path=fallback_normalized,
            )
        )
        return candidates[0]

    def _record_sort_key(
        self,
        *,
        record: EimCertificateRecord,
        allowed_ci_pkids: list[str],
        preferred_ci_pkids: list[str],
        fallback_path: str,
    ) -> tuple[Any, ...]:
        record_pkids = set(record.root_ci_pkids)
        match_allowed = len(record_pkids.intersection(allowed_ci_pkids)) > 0 if len(allowed_ci_pkids) > 0 else False
        match_preferred = len(record_pkids.intersection(preferred_ci_pkids)) > 0 if len(preferred_ci_pkids) > 0 else False
        normalized_path = self._normalize_path(record.certificate_path)
        basename = os.path.basename(record.certificate_path).upper()
        return (
            0 if (match_allowed and match_preferred) else 1,
            0 if match_allowed else 1,
            0 if match_preferred else 1,
            0 if normalized_path == self.identity_default_cert_path else 1,
            0 if normalized_path == fallback_path else 1,
            0 if "ACCEPTED" in basename else 1,
            0 if record.source == "local_eim_dir" else 1,
            0 if len(record.private_key_path) > 0 else 1,
            0 if record.curve == self.prefer_curve else 1,
            0 if len(record.root_ci_pkids) > 0 else 1,
            basename,
            record.certificate_path,
        )

    def _scan_roots(self) -> list[tuple[str, str]]:
        roots: list[tuple[str, str]] = []
        if os.path.isdir(self.local_cert_root):
            roots.append(("local_eim_dir", self.local_cert_root))
        if os.path.isdir(self.sgp26_valid_cert_root):
            roots.append(("sgp26_valid", self.sgp26_valid_cert_root))
        return roots

    def _iter_certificate_paths(self, root: str) -> list[str]:
        root_path = Path(root)
        entries: list[str] = []
        for path in sorted(root_path.rglob("*")):
            if path.is_file() is False:
                continue
            suffix = path.suffix.lower()
            if suffix not in self.CERTIFICATE_EXTENSIONS:
                continue
            basename = path.name.lower()
            if basename == "readme.md":
                continue
            if basename.endswith(".meta.json"):
                continue
            entries.append(str(path))
        return entries

    def _load_record(self, certificate_path: str, source: str) -> Optional[EimCertificateRecord]:
        normalized_path = self._normalize_path(certificate_path)
        if len(normalized_path) == 0:
            return None
        metadata = self._load_sidecar_metadata(normalized_path)
        raw_bytes = self._load_certificate_bytes(normalized_path)
        certificate: Optional[crypto_x509.Certificate] = None
        try:
            certificate = self._load_certificate(raw_bytes)
        except Exception:
            if len(metadata) == 0:
                return None
        role = self._record_role(normalized_path, certificate, metadata)
        if role not in ("signing", "tls", "ci"):
            return None
        private_key_path = self._private_key_path(normalized_path, metadata)
        subject = ""
        issuer = ""
        subject_cn = str(metadata.get("subject_cn", "")).strip()
        curve = str(metadata.get("curve", "")).strip().upper()
        ski = ""
        aki = ""
        der_bytes = bytes(raw_bytes)
        if certificate is not None:
            subject = certificate.subject.rfc4514_string()
            issuer = certificate.issuer.rfc4514_string()
            if len(subject_cn) == 0:
                subject_cn = self._subject_common_name(certificate)
            if len(curve) == 0:
                curve = self._curve_name(normalized_path, certificate)
            ski = self._subject_key_identifier(certificate)
            aki = self._authority_key_identifier(certificate)
            der_bytes = certificate.public_bytes(serialization.Encoding.DER)
        else:
            subject = str(metadata.get("subject", "")).strip()
            issuer = str(metadata.get("issuer", "")).strip()
            ski = self._normalize_ci_pkid(metadata.get("ski", ""))
            aki = self._normalize_ci_pkid(metadata.get("aki", ""))
        roots = self._root_ci_pkids(normalized_path, certificate, metadata)
        return EimCertificateRecord(
            role=role,
            source=source,
            certificate_path=normalized_path,
            private_key_path=private_key_path,
            subject=subject,
            issuer=issuer,
            subject_cn=subject_cn,
            curve=curve,
            ski=ski,
            aki=aki,
            root_ci_pkids=tuple(roots),
            der_bytes=der_bytes,
        )

    def _record_role(
        self,
        certificate_path: str,
        certificate: Optional[crypto_x509.Certificate],
        metadata: dict[str, Any],
    ) -> str:
        metadata_role = str(metadata.get("role", "")).strip().lower()
        if metadata_role in ("signing", "tls", "ci"):
            return metadata_role
        normalized = certificate_path.replace("\\", "/").lower()
        basename = os.path.basename(normalized)
        if "tls" in basename or "tls" in normalized:
            return "tls"
        if "/ci/" in normalized or basename.startswith("cert_ci_"):
            return "ci"
        if certificate is not None:
            try:
                constraints = certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                if bool(constraints.value.ca):
                    return "ci"
            except Exception:
                pass
            try:
                usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                if bool(usage.key_cert_sign):
                    return "ci"
            except Exception:
                pass
        return "signing"

    def _private_key_path(self, certificate_path: str, metadata: dict[str, Any]) -> str:
        explicit_text = str(metadata.get("private_key_path", "")).strip()
        explicit = ""
        if len(explicit_text) > 0:
            if os.path.isabs(explicit_text):
                explicit = self._normalize_path(explicit_text)
            else:
                explicit = self._normalize_path(
                    os.path.join(os.path.dirname(certificate_path), explicit_text)
                )
        if len(explicit) > 0 and os.path.isfile(explicit):
            return explicit
        directory = os.path.dirname(certificate_path)
        filename = os.path.basename(certificate_path)
        stem, _ = os.path.splitext(filename)
        guesses: list[str] = []
        if stem.startswith("CERT_"):
            guesses.append(os.path.join(directory, f"SK_{stem[5:]}.pem"))
        if stem.startswith("CERT."):
            guesses.append(os.path.join(directory, f"SK.{stem[5:]}.pem"))
        if stem.startswith("CERT_") and stem.endswith(".DER"):
            guesses.append(os.path.join(directory, f"SK_{stem[5:]}.pem"))
        for guess in guesses:
            if os.path.isfile(guess):
                return os.path.abspath(guess)
        return ""

    def _root_ci_pkids(
        self,
        certificate_path: str,
        certificate: Optional[crypto_x509.Certificate],
        metadata: dict[str, Any],
    ) -> list[str]:
        values: list[str] = []
        metadata_values = metadata.get("root_ci_pkids")
        if isinstance(metadata_values, list):
            for value in metadata_values:
                normalized = self._normalize_ci_pkid(value)
                if len(normalized) > 0 and normalized not in values:
                    values.append(normalized)
        metadata_single = self._normalize_ci_pkid(metadata.get("root_ci_pkid", ""))
        if len(metadata_single) > 0 and metadata_single not in values:
            values.append(metadata_single)
        if certificate is not None:
            aki = self._authority_key_identifier(certificate)
            if len(aki) > 0 and aki not in values:
                values.append(aki)
        if self._normalize_path(certificate_path) == self.identity_default_cert_path:
            if len(self.identity_default_ci_pkid) > 0 and self.identity_default_ci_pkid not in values:
                values.append(self.identity_default_ci_pkid)
        return values

    def _load_sidecar_metadata(self, certificate_path: str) -> dict[str, Any]:
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
    def _load_certificate_bytes(path: str) -> bytes:
        with open(path, "rb") as cert_file:
            return cert_file.read()

    @staticmethod
    def _load_certificate(cert_bytes: bytes) -> crypto_x509.Certificate:
        stripped = cert_bytes.lstrip()
        if stripped.startswith(b"-----BEGIN CERTIFICATE-----"):
            return crypto_x509.load_pem_x509_certificate(cert_bytes)
        return crypto_x509.load_der_x509_certificate(cert_bytes)

    @staticmethod
    def _normalize_path(path_text: Any) -> str:
        value = str(path_text or "").strip()
        if len(value) == 0:
            return ""
        return os.path.abspath(os.path.expanduser(os.path.expandvars(value)))

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

    @classmethod
    def _normalize_ci_pkid_list(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            clean = cls._normalize_ci_pkid(value)
            if len(clean) == 0:
                continue
            if clean in normalized:
                continue
            normalized.append(clean)
        return normalized

    @staticmethod
    def _subject_common_name(certificate: crypto_x509.Certificate) -> str:
        try:
            entries = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        except Exception:
            return ""
        if len(entries) == 0:
            return ""
        return str(entries[0].value).strip()

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
    def _curve_name(certificate_path: str, certificate: crypto_x509.Certificate) -> str:
        upper_path = str(certificate_path or "").upper()
        if "_NIST" in upper_path:
            return "NIST"
        if "_BRP" in upper_path:
            return "BRP"
        public_key = certificate.public_key()
        curve = getattr(public_key, "curve", None)
        curve_name = str(getattr(curve, "name", "") or "").strip().lower()
        if curve_name in ("secp256r1", "prime256v1"):
            return "NIST"
        if curve_name == "brainpoolp256r1":
            return "BRP"
        return ""

    def _source_for_path(self, path: str) -> str:
        normalized = self._normalize_path(path)
        if len(normalized) == 0:
            return "external"
        if len(self.local_cert_root) > 0 and normalized.startswith(self.local_cert_root):
            return "local_eim_dir"
        if len(self.sgp26_valid_cert_root) > 0 and normalized.startswith(self.sgp26_valid_cert_root):
            return "sgp26_valid"
        return "external"
