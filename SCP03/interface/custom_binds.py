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
# Copyright (c) 2026 Hampus Hellsberg and contributors
# -----------------------------------------------------------------------------

import json 
import os 
import sys 

current_dir =os .path .dirname (os .path .abspath (__file__ ))
root_dir =os .path .abspath (os .path .join (current_dir ,'../../'))
is_missing =False 
if root_dir not in sys .path :
    is_missing =True 
if is_missing :
    sys .path .insert (0 ,root_dir )

from SCP03 .interface .wizards_ui import InteractiveWizard 

class CommandBinder :
    def __init__ (self ,filepath ="binds.json"):
        self .filepath =filepath 
        self .binds ={}
        self ._load ()

    def _load (self ):
        has_file =False 
        if os .path .exists (self .filepath ):
            has_file =True 

        if has_file :
            try :
                with open (self .filepath ,'r')as f :
                    self .binds =json .load (f )
            except Exception as e :
                print (f"[-] Failed to load binds: {e}")

        is_missing =False 
        if has_file ==False :
            is_missing =True 

        if is_missing :
            self .binds ={
            "adm":"manage-pin verify 0a {0}"
            }
            self ._save ()

    def _save (self ):
        try :
            with open (self .filepath ,'w')as f :
                json .dump (self .binds ,f ,indent =4 )
        except Exception :
            pass 

    def add_bind (self ,trigger ,sequence ):
        self .binds [trigger .lower ()]=sequence 
        self ._save ()

    def del_bind (self ,trigger ):
        trigger_key =trigger .lower ()
        has_key =False 
        if trigger_key in self .binds :
            has_key =True 

        if has_key :
            del self .binds [trigger_key ]
            self ._save ()

    def resolve (self ,command_line ):
        parts =command_line .strip ().split ()

        is_empty =False 
        if len (parts )==0 :
            is_empty =True 

        if is_empty :
            return [command_line ]

        base_cmd =parts [0 ].lower ()

        has_bind =False 
        if base_cmd in self .binds :
            has_bind =True 

        is_unbound =False 
        if has_bind ==False :
            is_unbound =True 

        if is_unbound :
            return [command_line ]

        if has_bind :
            template =self .binds [base_cmd ]
            args =parts [1 :]
            resolved_cmd =template 

            idx =0 
            for arg in args :
                target ="{"+str (idx )+"}"

                has_target =False 
                if target in resolved_cmd :
                    has_target =True 

                if has_target :
                    resolved_cmd =resolved_cmd .replace (target ,arg )

                idx +=1 

            has_sequence =False 
            if ";"in resolved_cmd :
                has_sequence =True 

            if has_sequence :
                raw_cmds =resolved_cmd .split (";")
                clean_cmds =[]
                for c in raw_cmds :
                    clean_cmds .append (c .strip ())
                return clean_cmds 

            is_single =False 
            if has_sequence ==False :
                is_single =True 

            if is_single :
                return [resolved_cmd ]


def manage_binds_wizard (colors_ref ,binder ):
    wiz =InteractiveWizard ("Manage Custom Binds",colors_ref ,"Add, remove, or list command macros.")
    wiz .add_step ("action","Action (ADD, DEL, LIST) [Default: LIST]:",default ="LIST")
    wiz .add_step ("trigger","Trigger word (for ADD/DEL) [Default: SKIP]:",default ="SKIP")
    wiz .add_step ("sequence","Command sequence (for ADD) [Default: SKIP]:",default ="SKIP")

    res =wiz .run ()

    action =""
    has_action =False 
    if res .get ("action"):
        has_action =True 

    if has_action :
        action =res .get ("action").upper ()

    is_list =False 
    if action =="LIST":
        is_list =True 

    if is_list :
        print (f"\n{colors_ref.HEADER}--- Current Binds ---{colors_ref.ENDC}")
        for k ,v in binder .binds .items ():
            print (f"  {colors_ref.CYAN}{k}{colors_ref.ENDC} -> {v}")

    is_add =False 
    if action =="ADD":
        is_add =True 

    if is_add :
        trigger =res .get ("trigger")
        seq =res .get ("sequence")

        valid_add =False 
        if trigger !="SKIP":
            valid_add =True 

        is_seq_valid =False 
        if seq !="SKIP":
            is_seq_valid =True 

        valid_complete =False 
        if valid_add :
            if is_seq_valid :
                valid_complete =True 

        if valid_complete :
            binder .add_bind (trigger ,seq )
            print (f"{colors_ref.GREEN}[+] Added bind: {trigger} -> {seq}{colors_ref.ENDC}")

    is_del =False 
    if action =="DEL":
        is_del =True 

    if is_del :
        trigger =res .get ("trigger")

        valid_del =False 
        if trigger !="SKIP":
            valid_del =True 

        if valid_del :
            binder .del_bind (trigger )
            print (f"{colors_ref.GREEN}[+] Removed bind: {trigger}{colors_ref.ENDC}")