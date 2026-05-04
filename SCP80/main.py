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

import argparse
import sys 
import os 

from yggdrasim_common.process_debug import add_debug_argument, set_global_debug
from yggdrasim_common.quit_control import QuitAllRequested

def run_standalone ():
    current_dir =os .path .dirname (os .path .abspath (__file__ ))
    if current_dir not in sys .path :
        sys .path .insert (0 ,current_dir )

    if __package__ :
        from .cli import OtaShell 
    else :
        from cli import OtaShell 
    parser =argparse .ArgumentParser (description ="YggdraSIM SCP80 OTA Shell")
    parser .add_argument ("--cmd",type =str ,help ="Semicolon-separated commands for non-interactive execution")
    parser .add_argument ("--stdin",action ="store_true",help ="Read newline-separated commands from stdin for non-interactive execution")
    add_debug_argument (
    parser ,
    help_text ="Enable verbose debug output for this SCP80 session.",
    )
    args =parser .parse_args ()
    set_global_debug (bool (getattr (args ,"debug",False )))
    shell =OtaShell ()
    if args .cmd :
        shell .run_commands (args .cmd )
        return
    if args .stdin :
        command_lines =[]
        for raw_line in sys .stdin .read ().splitlines ():
            command_text =str (raw_line or "").strip ()
            if len (command_text )==0 :
                continue
            if command_text .startswith ("#"):
                continue
            command_lines .append (command_text )
        shell .run_commands ("; ".join (command_lines ))
        return
    shell .run ()

if __name__ =="__main__":
    try :
        run_standalone ()
    except QuitAllRequested :
        raise SystemExit (0 )