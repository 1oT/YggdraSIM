# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

from utils import Utils, Colors
from crypto import CryptoEngine
from config import ConfigManager

class OtaPacketBuilder:
    def __init__(self, config: ConfigManager):
        self.cfg = config

    def build(self, verbose: bool = False, override_payload: str = None) -> str:
        payload_hex = override_payload if override_payload else self.cfg.get("payload")
        if not payload_hex: 
            raise ValueError("Payload is empty")

        payload = Utils.to_bytes(payload_hex)
        spi_hex = self.cfg.get("spi")
        kic_hex = self.cfg.get("kic")
        kid_hex = self.cfg.get("kid")
        tar_hex = self.cfg.get("tar")
        cntr_hex = self.cfg.get("cntr")
        k_enc = Utils.to_bytes(self.cfg.get("key_enc"))
        k_mac = Utils.to_bytes(self.cfg.get("key_mac"))
        cla_hex = self.cfg.get("cla")

        cipher_mode = CryptoEngine.get_algo_type(kic_hex)
        mac_mode = CryptoEngine.get_algo_type(kid_hex)
        block_size = 16 if cipher_mode == "AES" else 8
        
        param_data = (Utils.to_bytes(spi_hex)[:2] + Utils.to_bytes(kic_hex)[:1] +
                      Utils.to_bytes(kid_hex)[:1] + Utils.to_bytes(tar_hex)[:3])
        cntr_bytes = Utils.to_bytes(cntr_hex)[:5]
        
        cc_len = 8
        pcntr = CryptoEngine.compute_pcntr(len(payload), block_size, cc_len)
        pcntr_byte = bytes([pcntr])
        payload_padded = payload + (b'\x00' * pcntr)
        
        ct_len = 5 + 1 + cc_len + len(payload_padded)
        chl_byte = b'\x15'
        cpl_val = len(chl_byte) + len(param_data) + ct_len
        cpl_byte = bytes([cpl_val])
        chi_byte = b'\x00'
        header_blob = chi_byte + cpl_byte + chl_byte
        
        mac_input = header_blob + param_data + cntr_bytes + pcntr_byte + payload_padded
        cc = CryptoEngine.compute_cc(mac_mode, k_mac, mac_input)
        enc_input = cntr_bytes + pcntr_byte + cc + payload_padded
        ct = CryptoEngine.encrypt_ct(cipher_mode, k_enc, enc_input)
        
        block_0348 = header_blob + param_data + ct
        d1_prefix = bytes.fromhex("02028281060280018B354005811250F341F62222222222222225027000")
        d1_content = d1_prefix + block_0348
        d1_tag = bytes([0xD1, len(d1_content)]) + d1_content
        cla_byte = int(cla_hex, 16)
        apdu = bytes([cla_byte, 0xC2, 0x00, 0x00, len(d1_tag)]) + d1_tag
        
        if verbose:
            self._print_verbose(cipher_mode, mac_mode, chi_byte, cpl_byte, chl_byte, 
                              param_data, cntr_bytes, pcntr, cc, ct, apdu)
        return apdu.hex().upper()

    def _print_verbose(self, cmode, mmode, chi, cpl, chl, params, cntr, pcntr, cc, ct, apdu):
        print(f"\n{Colors.CYAN}[=== 03.48 BLOCK BREAKDOWN ===]{Colors.ENDC}")
        print(f"ALG:    {cmode} / {mmode}")
        print(f"CNTR:   {cntr.hex().upper()}")
        print(f"APDU:   {Colors.GREEN}{apdu.hex().upper()}{Colors.ENDC}")