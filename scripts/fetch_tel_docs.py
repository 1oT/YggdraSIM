# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Download manifest for the standards library under docs/tel-docs/.

`docs/` is gitignored, so a fresh clone has no specification library; this script rebuilds the freely
published part of it (ETSI, 3GPP, IETF, ITU-T, NIST, SECG, BSI, USB-IF, PC/SC Workgroup) into
docs/tel-docs/, and `scripts/convert_tel_docs.py` then packs every new file for the `telecom_specs`
MCP server. Documents behind a licence click-through or a paywall (GSMA, GlobalPlatform, TCA, ISO,
Oracle) cannot be scripted; `--manual` prints that checklist with the file name each one must be
saved under.

ETSI file names follow the library's existing convention (`ts_102221v18.4.pdf`, trailing `.0`
dropped; a multi-part specification as `ts_102230-1v17.3.pdf`), so a refreshed release lands beside the
older edition instead of replacing it.
"""

from __future__ import annotations

import argparse
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = REPO_ROOT / "docs" / "tel-docs"
# The ETSI deliver server answers the urllib default agent with 403.
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"
PAUSE_SECONDS = 1.0
CHUNK_SIZE = 1 << 16

TIER_CITED = 1
TIER_FAMILY = 2


@dataclass(frozen=True)
class Source:
    filename: str
    url: str
    subject: str
    tier: int = TIER_CITED


def etsi(number: str, version: str, subject: str, tier: int = TIER_CITED, part: int | None = None) -> Source:
    """ETSI deliver URL for a published (_60) TS edition; `version` is the deliver form `18.04.00`.

    A multi-part specification is addressed by its base number plus `part` (the deliver server files
    TS 102 230-1 under `10223001`); the download is saved as `ts_102230-1v17.3.pdf` so the part stays
    visible in the library slug.
    """
    major, minor, _patch = (int(field) for field in version.split("."))
    short = f"{major}" if minor == 0 else f"{major}.{minor}"
    low = int(number) // 100 * 100
    group = f"{low:06d}_{low + 99:06d}"
    compact = version.replace(".", "")
    deliver_number = number if part is None else f"{number}{part:02d}"
    stem = f"ts_{number}" if part is None else f"ts_{number}-{part}"
    url = f"https://www.etsi.org/deliver/etsi_ts/{group}/{deliver_number}/{version}_60/ts_{deliver_number}v{compact}p.pdf"
    return Source(f"{stem}v{short}.pdf", url, subject, tier)


def rfc(number: int, subject: str, tier: int = TIER_CITED) -> Source:
    return Source(f"rfc{number}.txt", f"https://www.rfc-editor.org/rfc/rfc{number}.txt", subject, tier)


def itu(rec: str, edition: str, subject: str, tier: int = TIER_CITED) -> Source:
    ident = f"T-REC-{rec}-{edition}-I"
    url = f"https://www.itu.int/rec/dologin_pub.asp?lang=e&id={ident}!!PDF-E&type=items"
    return Source(f"{ident}_PDF-E.pdf", url, subject, tier)


def nist(filename: str, path: str, subject: str, tier: int = TIER_CITED) -> Source:
    return Source(filename, f"https://nvlpubs.nist.gov/nistpubs/{path}", subject, tier)


def pcsc(filename: str, subject: str) -> Source:
    return Source(filename, f"https://pcscworkgroup.com/Download/Specifications/{filename}", subject, TIER_CITED)


SOURCES: tuple[Source, ...] = (
    # ETSI SCP -- UICC platform
    etsi("101220", "19.00.00", "ETSI numbering system for telecommunication application providers (RID/AID)"),
    etsi("102221", "18.04.00", "UICC-Terminal interface; physical and logical characteristics"),
    etsi("102222", "17.01.00", "Administrative commands for telecommunications applications"),
    etsi("102223", "18.03.00", "Card Application Toolkit (CAT)"),
    etsi("102225", "19.00.00", "Secured packet structure for UICC based applications"),
    etsi("102226", "19.00.00", "Remote APDU structure for UICC based applications"),
    etsi("102240", "18.01.00", "UICC API and Loader Requirements; service description"),
    etsi("102241", "18.01.00", "UICC API for Java Card"),
    etsi("102310", "09.01.00", "Extensible Authentication Protocol support in the UICC"),
    etsi("102124", "06.01.00", "Transport protocol for CAT applications; stage 2"),
    etsi("102127", "15.00.00", "Transport protocol for CAT applications"),
    etsi("102412", "19.00.00", "Smart card platform requirements; stage 1"),
    etsi("102671", "19.00.00", "Machine to Machine UICC; physical and logical characteristics"),
    etsi("102484", "11.02.00", "Secure channel between a UICC and an end-point terminal", TIER_FAMILY),
    etsi("102230", "10.02.00", "UICC-Terminal interface; physical, electrical and logical test specification", TIER_FAMILY),
    etsi("102384", "17.00.00", "Card Application Toolkit (CAT) conformance test specification", TIER_FAMILY),
    etsi("102230", "17.03.00", "UICC-Terminal interface; physical, electrical and logical test specification; Part 1: Terminal features", TIER_FAMILY, part=1),
    etsi("102230", "17.05.00", "UICC-Terminal interface; physical, electrical and logical test specification; Part 2: UICC features", TIER_FAMILY, part=2),
    etsi("102268", "07.03.00", "Test specification for the UICC API for Java Card", TIER_FAMILY),
    etsi("103481", "16.06.00", "Test specification for the Remote APDU structure for UICC based applications; UICC features", TIER_FAMILY),
    etsi("103383", "14.00.00", "Embedded UICC; requirements specification", TIER_FAMILY),
    etsi("102588", "17.00.00", "Application invocation API by a UICC webserver for Java Card", TIER_FAMILY),
    etsi("102483", "12.00.00", "Identity management and smart cards", TIER_FAMILY),
    etsi("103465", "16.06.00", "Smart Secure Platform (SSP); requirements specification", TIER_FAMILY),
    # 3GPP CT6 -- USIM / ISIM / toolkit
    etsi("131101", "19.00.00", "UICC-terminal interface; physical and logical characteristics (3GPP)"),
    etsi("131102", "19.05.00", "Characteristics of the USIM application"),
    etsi("131103", "19.00.00", "Characteristics of the ISIM application"),
    etsi("131104", "19.00.00", "Characteristics of the Hosting Party Subscription Identity Module (HPSIM)", TIER_FAMILY),
    etsi("131105", "19.02.00", "Characteristics of the Slice Subscriber Identity Module (SSIM)", TIER_FAMILY),
    etsi("131111", "19.04.00", "USIM Application Toolkit (USAT)"),
    etsi("131115", "19.00.00", "Secured packet structure for (U)SIM Toolkit applications"),
    etsi("131116", "19.00.00", "Remote APDU structure for (U)SIM Toolkit applications"),
    etsi("131121", "18.06.00", "UICC-terminal interface; USIM application test specification"),
    etsi("131124", "18.07.00", "Mobile Equipment (ME) conformance test specification; USAT conformance test specification", TIER_FAMILY),
    etsi("131122", "18.06.00", "USIM conformance test specification (card side)", TIER_FAMILY),
    etsi("131213", "19.00.00", "Test specification for (U)SIM API for Java Card", TIER_FAMILY),
    etsi("131130", "19.02.00", "(U)SIM API for Java Card"),
    etsi("131220", "19.00.00", "Characteristics of the Contact Manager for 3GPP UICC applications"),
    etsi("131112", "08.00.00", "USAT Interpreter architecture", TIER_FAMILY),
    etsi("131113", "08.00.00", "USAT Interpreter byte codes", TIER_FAMILY),
    etsi("131114", "08.00.00", "USAT Interpreter protocol and administration", TIER_FAMILY),
    etsi("151014", "04.05.00", "SIM Application Toolkit (GSM 11.14)", TIER_FAMILY),
    etsi("151010", "13.15.00", "Mobile Station (MS) conformance specification; Part 1: Conformance specification (clause 27: SIM/ME interface)", TIER_FAMILY, part=1),
    etsi("151010", "19.00.00", "Mobile Station (MS) conformance specification; Part 4: SIM application toolkit conformance test specification", TIER_FAMILY, part=4),
    etsi("151013", "19.00.00", "Test specification for SIM API for Java Card", TIER_FAMILY),
    etsi("151017", "04.02.00", "SIM conformance test specification (card side)", TIER_FAMILY),
    etsi("143019", "06.00.00", "SIM API for Java Card (GSM)", TIER_FAMILY),
    # 3GPP core network / NAS / numbering
    etsi("122011", "19.06.00", "Service accessibility"),
    etsi("122022", "19.00.00", "Personalisation of Mobile Equipment (ME)", TIER_FAMILY),
    etsi("123003", "19.07.00", "Numbering, addressing and identification"),
    etsi("123008", "19.00.00", "Organization of subscriber data"),
    etsi("123038", "19.00.00", "Alphabets and language-specific information"),
    etsi("123040", "19.00.00", "Technical realization of the Short Message Service (SMS)"),
    etsi("123041", "19.04.00", "Technical realization of Cell Broadcast Service (CBS)"),
    etsi("123122", "19.07.00", "NAS functions related to Mobile Station in idle mode"),
    etsi("123401", "19.06.00", "GPRS enhancements for E-UTRAN access"),
    etsi("124008", "19.05.00", "Mobile radio interface Layer 3; core network protocols; stage 3"),
    etsi("124011", "19.00.00", "Point-to-point Short Message Service support on mobile radio interface"),
    etsi("124301", "19.07.00", "NAS protocol for EPS; stage 3"),
    etsi("124501", "19.07.00", "NAS protocol for 5GS; stage 3"),
    etsi("124526", "19.04.00", "UE policies for 5GS; stage 3"),
    etsi("127007", "19.06.00", "AT command set for User Equipment"),
    # 3GPP SA3 -- security and algorithms
    etsi("133102", "19.01.00", "3G security; security architecture"),
    etsi("133220", "19.01.00", "Generic Bootstrapping Architecture (GBA)"),
    etsi("133401", "19.02.00", "SAE; security architecture"),
    etsi("133402", "19.00.00", "SAE; security aspects of non-3GPP accesses"),
    etsi("133501", "19.07.00", "Security architecture and procedures for 5G System"),
    etsi("133535", "19.00.00", "Authentication and Key Management for Applications (AKMA)"),
    etsi("135205", "19.00.00", "MILENAGE algorithm set; general"),
    etsi("135206", "19.00.00", "MILENAGE algorithm specification"),
    etsi("135207", "19.00.00", "MILENAGE implementors' test data"),
    etsi("135208", "19.00.00", "MILENAGE design conformance test data"),
    etsi("135231", "19.00.00", "TUAK algorithm specification"),
    etsi("135232", "19.00.00", "TUAK implementers' test data"),
    etsi("135233", "19.00.00", "TUAK design conformance test data"),
    # ITU-T -- ASN.1, X.509, numbering
    itu("X.680", "202102", "ASN.1: specification of basic notation"),
    itu("X.681", "202102", "ASN.1: information object specification"),
    itu("X.682", "202102", "ASN.1: constraint specification"),
    itu("X.683", "202102", "ASN.1: parameterization of ASN.1 specifications"),
    itu("X.690", "202102", "ASN.1 encoding rules: BER, CER and DER"),
    itu("X.509", "201910", "Public-key and attribute certificate frameworks"),
    itu("X.660", "201107", "Object identifier registration procedures"),
    itu("E.118", "202509", "The international telecommunication charge card (ICCID)"),
    itu("E.212", "202406", "The international identification plan for public networks (IMSI)"),
    itu("E.164", "202602", "The international public telecommunication numbering plan"),
    itu("X.121", "200010", "International numbering plan for public data networks", TIER_FAMILY),
    # IETF -- TLS
    rfc(8446, "TLS 1.3"),
    rfc(5246, "TLS 1.2"),
    rfc(6066, "TLS extensions (SNI, max fragment length, status request)"),
    rfc(5289, "TLS ECC cipher suites with SHA-256/384 and AES-GCM"),
    rfc(8422, "ECC cipher suites for TLS 1.2 and earlier"),
    rfc(7027, "ECC brainpool curves for TLS"),
    rfc(4279, "Pre-shared key cipher suites for TLS"),
    rfc(4785, "Pre-shared key cipher suites with NULL encryption for TLS"),
    rfc(5487, "Pre-shared key cipher suites for TLS with SHA-256/384 and AES-GCM"),
    rfc(2818, "HTTP over TLS (server identity check)"),
    rfc(5116, "AEAD interface and algorithms"),
    rfc(6347, "DTLS 1.2"),
    rfc(9147, "DTLS 1.3"),
    rfc(8879, "TLS certificate compression"),
    rfc(7627, "TLS session hash and extended master secret", TIER_FAMILY),
    rfc(5746, "TLS renegotiation indication extension", TIER_FAMILY),
    rfc(5077, "TLS session resumption without server-side state (session tickets)", TIER_FAMILY),
    rfc(7301, "TLS application-layer protocol negotiation (ALPN)", TIER_FAMILY),
    # IETF -- PKIX and key formats
    rfc(5280, "X.509 PKI certificate and CRL profile"),
    rfc(5480, "Elliptic curve subject public key information"),
    rfc(5758, "ECDSA and DSA algorithm identifiers"),
    rfc(5915, "Elliptic curve private key structure"),
    rfc(5958, "Asymmetric key packages (PKCS #8 v2)"),
    rfc(5208, "PKCS #8: private-key information syntax v1.2"),
    rfc(8017, "PKCS #1: RSA cryptography v2.2"),
    rfc(4514, "LDAP string representation of distinguished names"),
    rfc(5639, "ECC Brainpool standard curves"),
    rfc(7748, "Elliptic curves for security (X25519, X448)"),
    rfc(6960, "Online Certificate Status Protocol (OCSP)", TIER_FAMILY),
    rfc(4648, "Base16, Base32 and Base64 encodings", TIER_FAMILY),
    # IETF -- EAP
    rfc(3748, "Extensible Authentication Protocol (EAP)"),
    rfc(4187, "EAP-AKA"),
    rfc(9048, "EAP-AKA' (improved)"),
    rfc(5216, "EAP-TLS"),
    rfc(9190, "EAP-TLS 1.3"),
    rfc(7542, "Network Access Identifier"),
    # IETF -- transport and text formats used by BIP / ES9+ / ESipa
    rfc(1035, "DNS implementation and specification"),
    rfc(7766, "DNS transport over TCP"),
    rfc(9110, "HTTP semantics"),
    rfc(9112, "HTTP/1.1"),
    rfc(3986, "URI generic syntax"),
    rfc(5952, "IPv6 address text representation", TIER_FAMILY),
    rfc(5737, "IPv4 address blocks reserved for documentation"),
    rfc(3849, "IPv6 address prefix reserved for documentation"),
    rfc(2606, "Reserved top level DNS names"),
    # NIST / FIPS
    nist("NIST.SP.800-108r1-upd1.pdf", "SpecialPublications/NIST.SP.800-108r1-upd1.pdf", "KDFs using pseudorandom functions (SCP03 key derivation)"),
    nist("NIST.SP.800-38A.pdf", "Legacy/SP/nistspecialpublication800-38a.pdf", "Block cipher modes: methods and techniques (CBC)"),
    nist("NIST.SP.800-38B.pdf", "SpecialPublications/NIST.SP.800-38B.pdf", "Block cipher modes: CMAC"),
    nist("NIST.SP.800-38D.pdf", "Legacy/SP/nistspecialpublication800-38d.pdf", "Block cipher modes: GCM and GMAC"),
    nist("NIST.SP.800-56Ar3.pdf", "SpecialPublications/NIST.SP.800-56Ar3.pdf", "Pair-wise key establishment using discrete logarithm cryptography (ECDH)"),
    nist("NIST.FIPS.186-5.pdf", "FIPS/NIST.FIPS.186-5.pdf", "Digital Signature Standard (ECDSA)"),
    nist("NIST.FIPS.197-upd1.pdf", "FIPS/NIST.FIPS.197-upd1.pdf", "Advanced Encryption Standard (AES)"),
    nist("NIST.FIPS.180-4.pdf", "FIPS/NIST.FIPS.180-4.pdf", "Secure Hash Standard (SHA-2)"),
    nist("NIST.FIPS.202.pdf", "FIPS/NIST.FIPS.202.pdf", "SHA-3 standard"),
    # Elliptic-curve parameter sources
    Source("sec1-v2.pdf", "https://www.secg.org/sec1-v2.pdf", "SEC 1: elliptic curve cryptography"),
    Source("sec2-v2.pdf", "https://www.secg.org/sec2-v2.pdf", "SEC 2: recommended elliptic curve domain parameters (secp256r1 etc.)"),
    Source(
        "BSI-TR-03111_V-2-1.pdf",
        "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-1_pdf.pdf?__blob=publicationFile",
        "BSI TR-03111: elliptic curve cryptography (Brainpool / GP key agreement)",
    ),
    # Reader / host interfaces
    Source("DWG_Smart-Card_CCID_Rev110.pdf", "https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf", "USB CCID device class rev 1.1"),
    pcsc("pcsc1_v2.01.01.pdf", "PC/SC part 1: introduction and architecture overview"),
    pcsc("pcsc2_v2.01.01.pdf", "PC/SC part 2: interoperability requirements for ICCs and IFDs"),
    pcsc("pcsc3_v2.01.09.pdf", "PC/SC part 3: requirements for PC-connected IFDs"),
    pcsc("pcsc3_v2.01.09_amd1.pdf", "PC/SC part 3 amendment 1"),
    pcsc("pcsc3_v2.01.09_sup.pdf", "PC/SC part 3 supplement: IFD subclasses"),
    pcsc("pcsc3_v2.02.00_sup2.pdf", "PC/SC part 3 supplement 2: contactless"),
    pcsc("pcsc4_v2.01.01.pdf", "PC/SC part 4: IFD design considerations"),
    pcsc("pcsc5_v2.01.01.pdf", "PC/SC part 5: ICC resource manager definition"),
    pcsc("pcsc6_v2.01.01.pdf", "PC/SC part 6: ICC service provider interface definition"),
    pcsc("pcsc7_v2.01.01.pdf", "PC/SC part 7: application domain and developer design considerations"),
    pcsc("pcsc8_v2.01.01.pdf", "PC/SC part 8: recommendations for ICC security and privacy devices"),
    pcsc("pcsc9_v2.01.01.pdf", "PC/SC part 9: IFDs with extended capabilities"),
    pcsc("pcsc10_v2.02.09.pdf", "PC/SC part 10: IFDs with secure PIN entry capabilities"),
    pcsc("pcsc10_v2.02.08_amd1.1.pdf", "PC/SC part 10 amendment 1.1"),
    pcsc("pcsc_addendum_v2.0.pdf", "PC/SC addendum v2.0"),
)

# (target file name, publisher page, subject) -- click-through licence or paywall, no scripted download.
MANUAL: tuple[tuple[str, str, str], ...] = (
    ("SGP.26-v3.0.2-TestCertificates.zip", "gsma.com eSIM specifications", "RSP test certificate archive for SGP.26 v3.0.2 (the PDF is in the library); unpack under converted/_assets/SGP.26-v3.0.2/"),
    ("SGP.26-v1.5-TestCertificates.zip", "gsma.com eSIM specifications", "RSP test certificate archive for the SGP.22 v2 line (the SGP.26 v1.5 PDF is in the library); unpack under converted/_assets/SGP.26-v1.5/"),
    ("SGP.02-v4.3.pdf", "gsma.com eSIM specifications", "M2M remote provisioning (the library packs the v4.2 Markdown rendering listed in convert_tel_docs.MARKDOWN_SOURCES; the PDF replaces it)"),
    ("SGP.22-v2.7.pdf", "gsma.com eSIM specifications", "RSP technical specification, v2 line (deployed cards are mostly v2)"),
    ("SGP.22-v2.5.pdf", "gsma.com eSIM specifications", "RSP technical specification v2.5, the version SGP.33-3 v1.2 cites as [2]"),
    ("SGP.23-3-v3.1.pdf", "gsma.com eSIM specifications", "RSP test specification for the servers (SM-DP+, SM-DS), v3 line; SGP.23-2 v3.1 cites it as [31]"),
    ("SGP.28-v1.0.pdf", "gsma.com eSIM specifications", "eSIM CI registration criteria"),
    ("SGP.21-v2.6.pdf", "gsma.com eSIM specifications", "RSP architecture, v2 line"),
    ("SGP.01-v4.3.pdf", "gsma.com eSIM specifications", "Embedded SIM remote provisioning architecture (M2M)"),
    ("SGP.11-v4.2.1.pdf", "gsma.com eSIM specifications", "M2M remote provisioning test specification"),
    ("GPC_CardSpecification_v2.3.1_PublicRelease.pdf", "globalplatform.org specs library", "Card Specification v2.3.1 (replaces the v2.3.1.49 public-review draft; v2.4 is in the library)"),
    ("GPC_2.3_B_RAM_over_HTTP_v1.2_PublicRelease.pdf", "globalplatform.org specs library", "Amendment B: remote application management over HTTP"),
    ("GPC_2.3_C_ContactlessServices_v1.3_PublicRelease.pdf", "globalplatform.org specs library", "Amendment C: contactless services"),
    ("GPC_2.3_D_SCP03_v1.2_PublicRelease.pdf", "globalplatform.org specs library", "Amendment D: SCP03 (library has v1.1.2)"),
    ("GPC_2.3_E_SecurityUpgrade_v1.1_PublicRelease.pdf", "globalplatform.org specs library", "Amendment E: security upgrade for card content management (ECC keys)"),
    ("GPC_2.3_F_SCP11_v1.4_PublicRelease.pdf", "globalplatform.org specs library", "Amendment F: SCP11 (SGP.22 §2.6 key agreement)"),
    ("GPC_2.3_H_ELF_Upgrade_v1.1_PublicRelease.pdf", "globalplatform.org specs library", "Amendment H: executable load file upgrade"),
    ("GPC_2.3_I_SEMS_v1.1_PublicRelease.pdf", "globalplatform.org specs library", "Amendment I: secure element management service"),
    ("GPC_2.3_M_RAM_over_CoAP_v1.0_PublicRelease.pdf", "globalplatform.org specs library", "Amendment M: remote application management over CoAP (TCA 3.4 [GP AM])"),
    ("GPD_SE_Access_Control_v1.1_PublicRelease.pdf", "globalplatform.org specs library", "Secure Element Access Control v1.1 (library has the v1.1.0.10 review draft)"),
    ("GPC_JavaCardAPI_v1.7.pdf", "globalplatform.org specs library", "Java Card API and export file for Card Specification"),
    ("eUICC_Profile_Package_Interoperable_Format_Technical_Specification_v2.3.1.pdf", "trustedconnectivityalliance.org", "SAIP v2 line (library has v3.4.1)"),
    ("ISO_IEC_7816-3_2006.pdf", "iso.org (paid)", "Cards with contacts: electrical interface and transmission protocols (ATR, T=0/T=1)"),
    ("ISO_IEC_7816-4_2020.pdf", "iso.org (paid)", "Organization, security and commands for interchange"),
    ("ISO_IEC_7816-5_2004.pdf", "iso.org (paid)", "Registration of application providers"),
    ("ISO_IEC_7816-6_2023.pdf", "iso.org (paid)", "Interindustry data elements for interchange"),
    ("ISO_IEC_7816-8_2021.pdf", "iso.org (paid)", "Commands and mechanisms for security operations"),
    ("ISO_IEC_7816-9_2017.pdf", "iso.org (paid)", "Commands for card management"),
    ("ISO_IEC_7816-15_2016.pdf", "iso.org (paid)", "Cryptographic information application"),
    ("ISO_IEC_7812-1_2017.pdf", "iso.org (paid)", "Identification cards: numbering system (IIN, Luhn)"),
    ("ISO_IEC_9797-1_2011.pdf", "iso.org (paid)", "MACs using a block cipher (Retail MAC / ISO 9797-1 M2 padding)"),
    ("pkcs-15v1_1.pdf", "RSA Laboratories archive mirrors", "PKCS #15 v1.1: cryptographic token information syntax (EF.DIR / EF.ODF layout); the library holds only the 1999 USENIX paper on it"),
    ("C.S0065-B_v2.0.pdf", "3gpp2.org specifications (site unreachable 2026-09-03)", "cdma2000 application on UICC (CSIM): the DF_CDMA file identifiers in SCP03/seeds/fids.txt"),
    ("C.S0074-A_v1.0.pdf", "3gpp2.org specifications (site unreachable 2026-09-03)", "CSIM application test specification; companion to C.S0065"),
)


def download(source: Source, force: bool) -> str:
    """Fetch one source into SOURCE_DIR; returns 'fetched', 'exists' or an error message."""
    target = SOURCE_DIR / source.filename
    if target.exists() and not force:
        return "exists"
    partial = target.with_suffix(target.suffix + ".part")
    request = urllib.request.Request(source.url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as handle:
            while True:
                chunk = response.read(CHUNK_SIZE)
                if not chunk:
                    break
                handle.write(chunk)
    except (urllib.error.URLError, OSError) as exc:
        partial.unlink(missing_ok=True)
        return f"error: {exc}"
    head = partial.read_bytes()[:8]
    if target.suffix.lower() == ".pdf" and not head.startswith(b"%PDF"):
        partial.unlink(missing_ok=True)
        return "error: response is not a PDF (licence page or moved URL)"
    if target.suffix.lower() == ".txt" and not head.strip():
        partial.unlink(missing_ok=True)
        return "error: empty response"
    partial.replace(target)
    return "fetched"


def print_manual() -> None:
    print("Documents to download by hand (PDFs go under docs/tel-docs/ with exactly this file name; archives are unpacked where the note says):")
    print()
    for filename, where, subject in MANUAL:
        mark = "x" if (SOURCE_DIR / filename).exists() else " "
        print(f"- [{mark}] `{filename}` -- {subject} ({where})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Download the freely published standards into docs/tel-docs/.")
    parser.add_argument("--force", action="store_true", help="re-download files that already exist")
    parser.add_argument("--only", metavar="STEM", action="append", default=[], help="fetch only sources whose file name contains STEM (repeatable)")
    parser.add_argument("--tier", type=int, default=TIER_FAMILY, choices=(TIER_CITED, TIER_FAMILY), help="highest tier to fetch: 1 = cited by the code, 2 = also the rest of each family (default)")
    parser.add_argument("--list", action="store_true", help="print the manifest instead of downloading")
    parser.add_argument("--manual", action="store_true", help="print the checklist of documents that cannot be scripted")
    args = parser.parse_args()

    if args.manual:
        print_manual()
        return 0

    selected = [source for source in SOURCES if source.tier <= args.tier]
    if args.only:
        selected = [source for source in selected if any(needle.lower() in source.filename.lower() for needle in args.only)]
        if not selected:
            parser.error(f"no source matches {args.only}")
    if args.list:
        for source in selected:
            print(f"{source.filename}\t{source.url}\t{source.subject}")
        return 0

    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    counts = {"fetched": 0, "exists": 0, "error": 0}
    for source in selected:
        result = download(source, args.force)
        key = "error" if result.startswith("error") else result
        counts[key] += 1
        print(f"{source.filename}: {result}", flush=True)
        if result == "fetched":
            time.sleep(PAUSE_SECONDS)
    print(f"fetched {counts['fetched']}, {counts['exists']} already present, {counts['error']} failed", flush=True)
    return 1 if counts["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
