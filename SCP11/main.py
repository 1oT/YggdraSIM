# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import sys
from sgp_utils import SGP22Transport, CryptoEngine, PayloadBuilder, ASN1Registry
from config import SGPConfig

class SGP22Client:
    def __init__(self):
        self.cfg = SGPConfig()
        self.tp = SGP22Transport()
        self.state = {} # Session Context

    def run_flow(self):
        print("--- 1OT / SGP.22 TOOL - REIMAGINED ---")
        
        try:
            self._initialize_card()
            self._load_keys()
            self._perform_handshake()
            self._authenticate_server()
            self._prepare_download()
            print("\n[SUCCESS] Sequence Completed.")
            
        except Exception as e:
            print(f"\n[CRITICAL ERROR] {e}")
            sys.exit(1)

    def _initialize_card(self):
        # 1. Term Cap
        try:
            self.tp.send(bytes.fromhex("80AA000007A9058303170000"), "INIT: TERMINAL CAPABILITY")
        except IOError: pass # Optional

        # 2. Select ISD-R
        cmd = b'\x00\xA4\x04\x00' + bytes([len(self.cfg.AID_ISD_R)]) + self.cfg.AID_ISD_R
        self.tp.send(cmd, "INIT: SELECT ISD-R")

    def _load_keys(self):
        print("\n[*] Loading Credentials...")
        self.cert_auth, self.key_auth = CryptoEngine.load_credentials(
            self.cfg.CERT_PATH_AUTH, self.cfg.KEY_PATH_AUTH
        )
        self.cert_pb, self.key_pb = CryptoEngine.load_credentials(
            self.cfg.CERT_PATH_PB, self.cfg.KEY_PATH_PB
        )
        print("[+] Credentials Loaded.")

    def _perform_handshake(self):
        # ES10b.GetEuiccInfo1
        self.tp.send(b'\x80\xE2\x91\x00\x03\xBF\x20\x00', "HANDSHAKE: GetEuiccInfo1")
        
        # ES10b.GetEuiccChallenge
        resp = self.tp.send(b'\x80\xE2\x91\x00\x03\xBF\x2E\x00', "HANDSHAKE: GetEuiccChallenge")
        
        # Extract last 16 bytes as challenge
        self.state['r_card'] = resp[-16:]
        print(f"[+] Card Challenge: {self.state['r_card'].hex().upper()}")

    def _authenticate_server(self):
        # 1. Generate Server Data
        signed1, t_id, r_server = CryptoEngine.generate_server_challenges(
            self.state['r_card'], self.cfg.RSP_SERVER_URL
        )
        self.state['t_id'] = t_id
        
        # 2. Sign
        signature = CryptoEngine.sign_asn1(signed1, self.key_auth)
        
        # 3. Build Payload
        ctx_params = {
            'matchingId': '', 
            'deviceInfo': {
                'tac': self.cfg.TAC,
                'deviceCapabilities': self.cfg.CAPABILITIES
            }
        }
        
        payload = PayloadBuilder.build_auth_server(
            signed1, signature, self.cert_auth, ctx_params, self.cfg.ROOT_CI_ID
        )

        # 4. Transmit
        resp = self.tp.send_chunked(
            0x80, 0xE2, 0x91, 0x00, payload, "AUTH: AuthenticateServer"
        )
        
        # 5. Parse Response (Manual Peel Logic)
        self._parse_auth_response(resp)

    def _parse_auth_response(self, data: bytes):
        print("\n[*] Parsing Auth Response...")
        
        # Validate Tag BF 38
        if data[:2] != b'\xBF\x38':
            raise ValueError("Invalid Response Tag (Expected BF38)")
            
        # Decode Length of Outer Tag
        offset = 2
        length_byte = data[offset]
        if length_byte < 0x80: start = offset + 1
        elif length_byte == 0x81: start = offset + 2
        elif length_byte == 0x82: start = offset + 3
        else: raise ValueError("Invalid Length encoding")
        
        inner_data = data[start:]
        
        # ASN.1 Load
        resp_obj = ASN1Registry.AuthenticateServerResponse.load(inner_data)
        
        if resp_obj.name == 'authenticateResponseError':
            raise PermissionError(f"Server Auth Refused by Card. Code: {resp_obj.native}")
            
        ok_data = resp_obj.chosen
        self.state['euicc_sig1'] = ok_data['euiccSignature1'].native
        print(f"[+] Captured euiccSignature1: {self.state['euicc_sig1'].hex()[:32]}...")

    def _prepare_download(self):
        print("\n[*] Phase: Prepare Download")
        
        payload = PayloadBuilder.build_prepare_download(
            self.state['t_id'],
            self.state['euicc_sig1'],
            self.cert_pb,
            self.key_pb
        )
        
        resp = self.tp.send_chunked(
            0x80, 0xE2, 0x91, 0x00, payload, "DOWNLOAD: PrepareDownload"
        )
        print(f"[+] otPK Response: {resp.hex()[:60]}...")

if __name__ == "__main__":
    client = SGP22Client()
    client.run_flow()