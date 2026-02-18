from dataclasses import dataclass

@dataclass(frozen=True)
class SGPConfig:
    """Configuration constants for SGP.26 emulation."""
    
    # Paths
    CERT_PATH_AUTH: str = "CERT.DPauth.ECDSA.der"
    KEY_PATH_AUTH: str = "SK.DPauth.ECDSA.pem"
    CERT_PATH_PB: str = "CERT.DPpb.ECDSA.der"
    KEY_PATH_PB: str = "SK.DPpb.ECDSA.pem"

    # Profile Protection Keys (Static fallback)
    STATIC_PPK_ENC: bytes = bytes.fromhex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    STATIC_PPK_MAC: bytes = bytes.fromhex("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

    # Identifiers
    AID_ISD_R: bytes = bytes.fromhex("A0000005591010FFFFFFFF8900000100")
    ROOT_CI_ID: bytes = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
    RSP_SERVER_URL: str = "rsp.example.com"

    # Device Info
    TAC: bytes = bytes.fromhex("01020304")
    CAPABILITIES: dict = None

    def __post_init__(self):
        # Initialize mutable defaults if necessary
        if self.CAPABILITIES is None:
            object.__setattr__(self, 'CAPABILITIES', {
                'gsmSupportedRelease': b'\x99\x00\x00',
                'utranSupportedRelease': b'\x99\x00\x00',
                'eutranEpcSupportedRelease': b'\x99\x00\x00'
            })