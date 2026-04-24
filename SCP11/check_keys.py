# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

from sgp_utils import CryptoEngine 
from cryptography .hazmat .primitives import hashes 
from cryptography .hazmat .primitives .asymmetric import ec 

def _hex_to_ansi (hex_color :str )->str :
    hex_value =hex_color .lstrip ('#')
    red =int (hex_value [0 :2 ],16 )
    green =int (hex_value [2 :4 ],16 )
    blue =int (hex_value [4 :6 ],16 )
    return f"\033[38;2;{red};{green};{blue}m"

PASS_COLOR =_hex_to_ansi ('#8DFF8D')
ERROR_COLOR =_hex_to_ansi ('#FF9A9A')
END_COLOR ='\033[0m'

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
            print (f"{PASS_COLOR}[PASS] Key Pair matches for {cert_name}.{END_COLOR}\n")

        except FileNotFoundError :
            print (f"{ERROR_COLOR}[ERROR] Files not found.{END_COLOR}\n")
        except Exception as e :
            print (f"{ERROR_COLOR}[FAIL] Verification Failed: {e}{END_COLOR}\n")

if __name__ =="__main__":
    KeyDiagnostics .verify_pair ("CERT.DPauth.ECDSA.der","SK.DPauth.ECDSA.pem")
    KeyDiagnostics .verify_pair ("CERT.DPpb.ECDSA.der","SK.DPpb.ECDSA.pem")