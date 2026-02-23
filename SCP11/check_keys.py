# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

from sgp_utils import CryptoEngine 
from cryptography .hazmat .primitives import hashes 
from cryptography .hazmat .primitives .asymmetric import ec 

class KeyDiagnostics :
    @staticmethod 
    def verify_pair (cert_name :str ,key_name :str ):
        print (f"--- DIAGNOSTIC: {cert_name} vs {key_name} ---")
        try :
            cert ,priv_key =CryptoEngine .load_credentials (cert_name ,key_name )
            pub_key =cert .public_key 

            data =b"SGP.22 Integrity Check"
            signature =priv_key .sign (data ,ec .ECDSA (hashes .SHA256 ()))

            pub_key .verify (signature ,data ,ec .ECDSA (hashes .SHA256 ()))
            print (f"\033[92m[PASS] Key Pair matches for {cert_name}.\033[0m\n")

        except FileNotFoundError :
            print (f"\033[91m[ERROR] Files not found.\033[0m\n")
        except Exception as e :
            print (f"\033[91m[FAIL] Verification Failed: {e}\033[0m\n")

if __name__ =="__main__":
    KeyDiagnostics .verify_pair ("CERT.DPauth.ECDSA.der","SK.DPauth.ECDSA.pem")
    KeyDiagnostics .verify_pair ("CERT.DPpb.ECDSA.der","SK.DPpb.ECDSA.pem")