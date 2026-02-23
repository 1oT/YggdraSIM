# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import sys 
import os 

def run_standalone ():
    current_dir =os .path .dirname (os .path .abspath (__file__ ))
    if current_dir not in sys .path :
        sys .path .insert (0 ,current_dir )

    from cli import OtaShell 
    OtaShell ().run ()

if __name__ =="__main__":
    run_standalone ()