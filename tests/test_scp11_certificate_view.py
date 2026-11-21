# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Certificate rows behind the ES10b GetCerts printers (SCP11/shared/certificate_view.py)."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import unittest
import warnings
from pathlib import Path

from cryptography.utils import CryptographyDeprecationWarning

from SCP03.core.utils import TlvParser
from SCP03.logic.sgp22 import Sgp22Manager
from SCP11.shared.certificate_view import (
    CertificateRow,
    certificate_rows,
    chain_rows,
    finding_rows,
    format_certificate_rows,
    get_certs_rows,
    tls_certificate_rows,
)
from SCP11.shared.discovery_snapshot import _print_get_certs_compact
from tests.certificate_view_support import (
    EID,
    EIN,
    NOW,
    ROLE_EUICC,
    ROLE_EUM,
    ROLE_EUM_V2,
    SERVER_HOST,
    build_chain,
    build_tls_chain,
    get_certs_response,
    leaf,
    tampered,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SGP26_OV3 = _REPO_ROOT / "SCP11" / "SGP.26_test_Certs" / "Valid Test Cases" / "Variant Ov3"

# The decode-boundary inputs of the coding standards: empty, one byte, a truncated TLV header,
# a length that over-claims its body and a long-form length with no body.
_MALFORMED = (
    b"",
    b"\x30",
    b"\x30\x82\x01",
    b"\x30\x05\x02\x01\x01",
    b"\x30\x82\x01\x00",
)


def _by_label(rows: list[CertificateRow]) -> dict[str, CertificateRow]:
    labelled: dict[str, CertificateRow] = {}
    for row in rows:
        labelled.setdefault(row.label, row)
    return labelled


class _Transport:
    debug = False


class CertificateRowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = build_chain()

    def test_eum_rows_name_the_role_and_decode_the_rsp_extensions(self) -> None:
        rows = _by_label(certificate_rows(self.chain.eum, now=NOW))

        self.assertEqual(rows["Subject"].value, "CN=ACME EUM, O=ACME, C=XX")
        self.assertEqual(rows["RSP Role"].value, f"id-rspRole-eum ({ROLE_EUM})")
        self.assertEqual(rows["Permitted EINs"].value, EIN)
        self.assertEqual(rows["Name Constraints"].value, "[critical] permitted DirName:O=ACME")
        self.assertEqual(rows["Key Usage"].value, "[critical] keyCertSign, cRLSign")
        self.assertEqual(rows["Basic Constraints"].value, "[critical] CA, path length 0")
        self.assertNotIn("EID", rows)

    def test_euicc_rows_carry_the_eid(self) -> None:
        rows = _by_label(certificate_rows(self.chain.euicc, now=NOW))

        self.assertEqual(rows["RSP Role"].value, f"id-rspRole-euicc ({ROLE_EUICC})")
        self.assertEqual(rows["EID"].value, EID)
        self.assertEqual(rows["Key Usage"].value, "[critical] digitalSignature")

    def test_variant_o_role_keeps_its_v2_name(self) -> None:
        chain = build_chain(eum_role=ROLE_EUM_V2)

        rows = _by_label(certificate_rows(chain.eum, now=NOW))

        self.assertEqual(rows["RSP Role"].value, f"id-rspRole-eum-v2 ({ROLE_EUM_V2})")

    def test_der_row_only_on_request(self) -> None:
        self.assertNotIn("DER Hex", _by_label(certificate_rows(self.chain.eum, now=NOW)))
        rows = _by_label(certificate_rows(self.chain.eum, now=NOW, include_der=True))
        self.assertEqual(rows["DER Hex"].value, self.chain.eum.hex().upper())

    def test_validity_is_judged_against_the_given_time(self) -> None:
        day = dt.timedelta(days=1)
        cases = (
            (leaf(not_before=NOW - 400 * day, not_after=NOW - 3 * day), "EXPIRED 3 days ago", "fail"),
            (leaf(not_before=NOW + 10 * day, not_after=NOW + 400 * day), "not yet valid, starts in 10 days", "fail"),
            (leaf(not_before=NOW - day, not_after=NOW + 12 * day), "valid, 12 days left", "warn"),
            (leaf(not_before=NOW - day, not_after=NOW + 400 * day), "valid, 1 year left", "ok"),
        )
        for der, status, tone in cases:
            with self.subTest(status=status):
                row = _by_label(certificate_rows(der, now=NOW))["Valid Until"]
                self.assertTrue(row.value.endswith(f"({status})"), row.value)
                self.assertEqual(row.tone, tone)

    def test_non_positive_serial_is_marked_and_kept_off_stderr(self) -> None:
        der = leaf(not_before=NOW - dt.timedelta(days=1), not_after=NOW + dt.timedelta(days=400))
        # version [0] v3, then serialNumber INTEGER 1 -> INTEGER 0
        self.assertEqual(der.count(bytes.fromhex("A003020102020101")), 1)
        zero_serial = der.replace(bytes.fromhex("A003020102020101"), bytes.fromhex("A003020102020100"))

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            rows = _by_label(certificate_rows(zero_serial, now=NOW))

        self.assertEqual(rows["Serial Number"].value, "00 (not positive, RFC 5280 §4.1.2.2)")
        self.assertEqual(rows["Serial Number"].tone, "warn")
        self.assertEqual([entry for entry in caught if issubclass(entry.category, CryptographyDeprecationWarning)], [])


class ChainRowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = build_chain()

    def test_get_certs_rows_verify_the_euicc_against_the_eum(self) -> None:
        rows = get_certs_rows(self.chain.eum, self.chain.euicc, now=NOW)
        chain = rows[[row.label for row in rows].index("Chain") + 1:]
        ci_ski = _by_label(certificate_rows(self.chain.ci, now=NOW))["Subject Key Identifier"].value

        self.assertEqual([row.label for row in chain], ["EUM Certificate", "`-- eUICC Certificate"])
        self.assertEqual(chain[0].value, f"issuer not in the response, AKI {ci_ski}")
        self.assertEqual((chain[1].value, chain[1].tone), ("signature valid", "ok"))

    def test_full_chain_nests_under_the_self_signed_ci(self) -> None:
        rows = chain_rows([("eUICC", self.chain.euicc), ("CI", self.chain.ci), ("EUM", self.chain.eum)])

        self.assertEqual(
            [(row.indent, row.label, row.value) for row in rows],
            [
                (0, "CI", "self-signed, signature valid"),
                (1, "`-- EUM", "signature valid"),
                (2, "`-- eUICC", "signature valid"),
            ],
        )

    def test_tampered_signature_is_reported_invalid(self) -> None:
        rows = chain_rows([("EUM", self.chain.eum), ("eUICC", tampered(self.chain.euicc))])

        self.assertEqual((rows[1].value, rows[1].tone), ("signature INVALID", "fail"))


def _server_name_row(rows: list[CertificateRow]) -> tuple[str, str]:
    row = [row for row in rows if row.label == "server name"][0]
    return row.value, row.tone


class TlsCertificateRowsTests(unittest.TestCase):
    """A TLS server's certificate_list (RFC 5246 §7.4.2) as the BIP observer hands it over."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = build_tls_chain()

    def test_a_served_chain_reads_as_headings_fields_and_links(self) -> None:
        rows = tls_certificate_rows((self.chain.server, self.chain.root), server_name=SERVER_HOST, now=NOW)

        self.assertEqual(
            [(row.indent, row.label, row.value) for row in rows[:6] if row.label != "valid"],
            [
                (0, "certificate [0]", SERVER_HOST),
                (1, "issuer", "Test CI"),
                (1, "subjectAltName", f"DNS:{SERVER_HOST}"),
                (1, "public key", "EC 256 bits, secp256r1"),
                (1, "RSP role", "id-rspRole-dp-tls-v2"),
            ],
        )
        self.assertEqual(rows[2].tone, "ok")
        self.assertIn("(valid, 1 year left)", rows[2].value)
        chain = rows[[row.label for row in rows].index("chain") + 1:-1]
        self.assertEqual(
            [(row.indent, row.label, row.value) for row in chain],
            [(1, "[1]", "self-signed, signature valid"), (2, "`-- [0]", "signature valid")],
        )
        self.assertEqual(_server_name_row(rows), (f"{SERVER_HOST} matches DNS:{SERVER_HOST}", "ok"))
        self.assertEqual(finding_rows(rows), [])

    def test_an_expired_server_certificate_is_a_finding(self) -> None:
        chain = build_tls_chain(not_before=NOW - dt.timedelta(days=400), not_after=NOW - dt.timedelta(days=3))

        findings = finding_rows(tls_certificate_rows((chain.server, chain.root), server_name=SERVER_HOST, now=NOW))

        self.assertEqual([(row.label, row.tone) for row in findings], [("certificate [0] valid", "fail")])
        self.assertIn("(EXPIRED 3 days ago)", findings[0].value)

    def test_a_certificate_near_its_end_is_a_warning(self) -> None:
        chain = build_tls_chain(not_after=NOW + dt.timedelta(days=12))

        findings = finding_rows(tls_certificate_rows((chain.server,), now=NOW))

        self.assertEqual([(row.label, row.tone) for row in findings], [("certificate [0] valid", "warn")])

    def test_a_name_the_certificate_does_not_carry_fails(self) -> None:
        rows = tls_certificate_rows((self.chain.server,), server_name="other.example.test", now=NOW)

        self.assertEqual(
            _server_name_row(rows),
            (f"other.example.test matches no dNSName (DNS:{SERVER_HOST})", "fail"),
        )
        self.assertEqual([row.label for row in finding_rows(rows)], ["server name"])

    def test_a_wildcard_stands_for_one_label_or_part_of_one(self) -> None:
        """RFC 2818 §3.1: *.a.com matches foo.a.com but not bar.foo.a.com; f*.com matches foo.com."""
        label = build_tls_chain(dns_names=("*.example.test",))
        fragment = build_tls_chain(dns_names=("f*.example.test",))

        def tone(chain_der: bytes, host: str) -> str:
            return _server_name_row(tls_certificate_rows((chain_der,), server_name=host, now=NOW))[1]

        self.assertEqual(tone(label.server, SERVER_HOST), "ok")
        self.assertEqual(tone(label.server, f"a.{SERVER_HOST}"), "fail")
        self.assertEqual(tone(fragment.server, "foo.example.test"), "ok")
        self.assertEqual(tone(fragment.server, "bar.example.test"), "fail")

    def test_without_a_dns_name_the_common_name_is_the_identity(self) -> None:
        chain = build_tls_chain(dns_names=())

        rows = tls_certificate_rows((chain.server,), server_name="SMDP.Example.Test.", now=NOW)

        self.assertEqual(
            _server_name_row(rows),
            (f"{SERVER_HOST} matches CN={SERVER_HOST} (no dNSName)", "ok"),
        )
        self.assertNotIn("subjectAltName", [row.label for row in rows])

    def test_a_root_left_out_names_the_authority_key(self) -> None:
        """RFC 5246 §7.4.2 lets the server leave its self-signed root out."""
        rows = tls_certificate_rows((self.chain.server,), now=NOW)
        root_ski = _by_label(certificate_rows(self.chain.root, now=NOW))["Subject Key Identifier"].value

        self.assertEqual(rows[-1].label, "[0]")
        self.assertEqual((rows[-1].value, rows[-1].tone), (f"issuer not sent, AKI {root_ski}", ""))
        self.assertNotIn("server name", [row.label for row in rows])

    def test_a_tampered_signature_is_a_finding_under_the_chain(self) -> None:
        rows = tls_certificate_rows((tampered(self.chain.server), self.chain.root), now=NOW)

        self.assertEqual(
            [(row.label, row.value, row.tone) for row in finding_rows(rows)],
            [("chain [0]", "signature INVALID", "fail")],
        )

    def test_a_certificate_that_does_not_parse_keeps_its_heading(self) -> None:
        for payload in _MALFORMED:
            with self.subTest(payload=payload.hex()):
                rows = tls_certificate_rows((payload, self.chain.root), server_name=SERVER_HOST, now=NOW)

                self.assertEqual((rows[0].label, rows[0].tone), ("certificate [0]", "fail"))
                self.assertTrue(rows[0].value.startswith("not an X.509 certificate"))
                self.assertIn("certificate [1]", [row.label for row in rows])
                self.assertEqual(
                    _server_name_row(rows),
                    (f"{SERVER_HOST} not checked: certificate [0] does not parse", "fail"),
                )

    def test_an_empty_list_has_no_rows(self) -> None:
        self.assertEqual(tls_certificate_rows((), server_name=SERVER_HOST, now=NOW), [])


class MalformedInputTests(unittest.TestCase):
    def test_certificate_rows_report_a_decode_error(self) -> None:
        for payload in _MALFORMED:
            with self.subTest(payload=payload.hex()):
                rows = certificate_rows(payload, include_der=True)
                self.assertEqual((rows[0].label, rows[0].tone), ("Decode error", "fail"))

    def test_chain_rows_skip_what_does_not_parse(self) -> None:
        for payload in _MALFORMED:
            with self.subTest(payload=payload.hex()):
                self.assertEqual(chain_rows([("X", payload)]), [])

    def test_get_certs_rows_keep_the_heading_of_an_unparsable_certificate(self) -> None:
        for payload in _MALFORMED[1:]:
            with self.subTest(payload=payload.hex()):
                rows = get_certs_rows(payload, None)
                self.assertEqual(rows[0].label, "EUM Certificate")
                self.assertEqual(rows[1].label, "Decode error")
        self.assertEqual(get_certs_rows(b"", None), [])


class FormatTests(unittest.TestCase):
    def test_values_share_one_column_and_continuations_align(self) -> None:
        rows = [
            CertificateRow(0, "Subject", "CN=probe"),
            CertificateRow(0, "Extensions", ""),
            CertificateRow(1, "Subject Alternative Name", "DNS:a.example.test"),
            CertificateRow(1, "", "DNS:b.example.test"),
            CertificateRow(0, "Valid Until", "expired", "fail"),
        ]

        lines = format_certificate_rows(rows, prefix="| ", palette={"fail": "<F>", "end": "</F>"})

        self.assertEqual(lines[1], "| Extensions")
        value_column = lines[0].index("CN=probe")
        self.assertEqual(lines[2].index("DNS:a"), value_column)
        self.assertEqual(lines[3].index("DNS:b"), value_column)
        self.assertTrue(lines[4].endswith(": <F>expired</F>"))
        for labelled in (lines[0], lines[2]):
            # Every label, the longest included, keeps a space before its colon.
            self.assertEqual(labelled[value_column - 3:value_column], " : ")


class PrinterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = build_chain()
        cls.response = get_certs_response(cls.chain.eum, cls.chain.euicc)

    def test_discovery_snapshot_prints_the_view_and_keeps_the_der_lines(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            _print_get_certs_compact(self.response)
        rendered = output.getvalue()

        self.assertIn("Permitted EINs", rendered)
        self.assertIn("`-- eUICC Certificate", rendered)
        self.assertIn("signature valid", rendered)
        self.assertIn(f"EUM Cert DER Hex    : {self.chain.eum.hex().upper()}", rendered)
        self.assertIn(f"eUICC Cert DER Hex  : {self.chain.euicc.hex().upper()}", rendered)

    def test_scp03_printers_render_the_view_for_both_entry_points(self) -> None:
        manager = Sgp22Manager(_Transport())
        # The parsed-tree entry point reads the BF56 value as raw bytes.
        parsed = TlvParser.parse(self.response, primitive_tags=[0xBF56])
        # The certs value exceeds 255 octets, so the rebuilt BF56 header needs a two-octet length.
        self.assertGreater(len(TlvParser.get_first(parsed, 0xBF56)), 0xFF)
        for render in (
            lambda: manager._print_get_certs_compact_response(self.response),
            lambda: manager._print_get_certs_compact(parsed),
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                render()
            rendered = output.getvalue()
            self.assertIn("Permitted EINs", rendered)
            self.assertIn("signature valid", rendered)
            self.assertIn(self.chain.euicc.hex().upper(), rendered)


class Sgp26ReferenceTests(unittest.TestCase):
    """The Variant Ov3 NIST chain of the SGP.26 v3.0.2 bundle, when the checkout holds it in clear."""

    def setUp(self) -> None:
        self.paths = {
            "CI": _SGP26_OV3 / "CI" / "CERT_CI_SIG_NIST.der",
            "EUM": _SGP26_OV3 / "EUM" / "CERT_EUM_SIG_NIST.der",
            "eUICC": _SGP26_OV3 / "eUICC" / "CERT_EUICC_SIG_NIST.der",
        }
        for path in self.paths.values():
            if not path.is_file() or path.read_bytes()[:1] != b"\x30":
                self.skipTest(f"SGP.26 certificate absent or encrypted: {path.relative_to(_REPO_ROOT)}")

    def test_variant_ov3_chain_reads_like_the_bundle(self) -> None:
        der = {name: path.read_bytes() for name, path in self.paths.items()}

        eum = _by_label(certificate_rows(der["EUM"], now=NOW))
        euicc = _by_label(certificate_rows(der["eUICC"], now=NOW))
        links = chain_rows([(name, value) for name, value in der.items()])

        self.assertEqual(eum["RSP Role"].value, f"id-rspRole-eum ({ROLE_EUM})")
        self.assertEqual(eum["Permitted EINs"].value, "89049032")
        self.assertEqual(euicc["RSP Role"].value, f"id-rspRole-euicc ({ROLE_EUICC})")
        self.assertEqual(euicc["EID"].value, "89049032123451234512345678901235")
        self.assertEqual([row.value for row in links], ["self-signed, signature valid", "signature valid", "signature valid"])


if __name__ == "__main__":
    unittest.main()
