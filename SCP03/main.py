# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import sys 
import os 




current_dir =os .path .dirname (os .path .abspath (__file__ ))
parent_dir =os .path .dirname (current_dir )
if parent_dir not in sys .path :
    sys .path .insert (0 ,parent_dir )


try :
    from SCP03 .interface .shell import ShellDispatcher 
except ImportError as e :
    print (f"Critical Import Error: {e}")
    print ("Ensure you are running this from the correct directory or that 'SCP03' is strictly a subdirectory.")
    sys .exit (1 )

def run_script (file_path ):
    try :
        app =ShellDispatcher ()
        app .run_script (file_path )
    except KeyboardInterrupt :
        print ("\n[SCP03] Script execution terminated by user.")
    except Exception as e :
        print (f"\n[SCP03] Fatal Error: {e}")

def run_report_wizard ():
    from SCP03 .interface .shell_wizards import ShellInteractiveWizards 
    try :
        app =ShellDispatcher ()
        ShellInteractiveWizards .run_fs_report_wizard (app )
    except KeyboardInterrupt :
        print ("\n[SCP03] Report wizard terminated by user.")
    except Exception as e :
        print (f"\n[SCP03] Fatal Error: {e}")

def entry ():
    """
    Public entry point. 
    The high-level wrapper should import this function to start the module.
    Example: 
        import SCP03.main as scp03_feature
        scp03_feature.entry()
    """
    try :
        app =ShellDispatcher ()
        app .run ()
    except KeyboardInterrupt :
        print ("\n[SCP03] Session terminated by user.")
    except Exception as e :
        print (f"\n[SCP03] Fatal Error: {e}")


def entry_cmd (cmd_line :str ,yaml_out :str =None ):
    """
    Non-interactive entry: run semicolon-separated commands and optionally write output to YAML.
    Example: entry_cmd("AUTH-SD; LIST", "report.yaml")
    """
    try :
        app =ShellDispatcher ()
        app .run_commands (cmd_line ,yaml_out =yaml_out )
    except KeyboardInterrupt :
        print ("\n[SCP03] Interrupted.")
    except Exception as e :
        print (f"\n[SCP03] Fatal Error: {e}")
        raise 


if __name__ =="__main__":
    import argparse 
    parser =argparse .ArgumentParser (description ="YggdraSIM SCP03 Admin Shell")
    parser .add_argument ("--cmd",type =str ,help ="Semicolon-separated commands (non-interactive)")
    parser .add_argument ("--out",type =str ,help ="Output YAML file for --cmd")
    args =parser .parse_args ()
    if args .cmd :
        entry_cmd (args .cmd ,yaml_out =args .out )
    else :
        entry ()