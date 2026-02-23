# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import zipfile 
import os 
from typing import Tuple ,List ,Optional 

class CapFileParser :

    ORDER =[
    'Header.cap',
    'Directory.cap',
    'Import.cap',
    'Applet.cap',
    'Class.cap',
    'Method.cap',
    'StaticField.cap',
    'Export.cap',
    'ConstantPool.cap',
    'RefLocation.cap',
    'Descriptor.cap'
    ]

    @staticmethod 
    def parse (cap_path :str )->Tuple [bytes ,bytes ,List [bytes ]]:
        """
        Parses a CAP (Zip) or IJC (Raw) file.
        Returns: (LoadFileBlock, PackageAID, List[AppletAIDs])
        """
        if not os .path .exists (cap_path ):
            raise FileNotFoundError (f"File not found: {cap_path}")

        if cap_path .lower ().endswith ('.ijc'):
            return CapFileParser ._parse_ijc (cap_path )
        else :
            return CapFileParser ._parse_cap (cap_path )

    @staticmethod 
    def _parse_ijc (ijc_path :str )->Tuple [bytes ,bytes ,List [bytes ]]:
        """
        Parses a pre-arranged .ijc file directly.
        Iterates over the component tags to extract metadata.
        """
        with open (ijc_path ,'rb')as f :
            data =f .read ()

        pkg_aid =b''
        applet_aids =[]
        offset =0 
        data_len =len (data )


        while offset <data_len :
            if offset +3 >data_len :
                break 

            tag =data [offset ]
            size =int .from_bytes (data [offset +1 :offset +3 ],byteorder ='big')
            comp_data =data [offset :offset +3 +size ]

            if tag ==1 :

                pkg_aid =CapFileParser ._extract_pkg_aid (comp_data )
            elif tag ==3 :

                applet_aids =CapFileParser ._extract_applet_aids (comp_data )

            offset +=3 +size 

        return data ,pkg_aid ,applet_aids 

    @staticmethod 
    def _parse_cap (cap_path :str )->Tuple [bytes ,bytes ,List [bytes ]]:
        """
        Parses a standard .cap ZIP archive file.
        Extracts, orders, and concatenates the internal .cap components.
        """
        blob =bytearray ()
        pkg_aid =b''
        applet_aids =[]

        try :
            with zipfile .ZipFile (cap_path ,'r')as z :

                all_files =z .namelist ()
                component_map ={}
                for f in all_files :
                    if f .lower ().endswith ('.cap'):
                        base =os .path .basename (f )
                        component_map [base ]=f 


                for comp_name in CapFileParser .ORDER :
                    if comp_name in component_map :
                        path =component_map [comp_name ]
                        data =z .read (path )
                        blob .extend (data )


                        if comp_name =='Header.cap':
                            pkg_aid =CapFileParser ._extract_pkg_aid (data )
                        elif comp_name =='Applet.cap':
                            applet_aids =CapFileParser ._extract_applet_aids (data )

        except zipfile .BadZipFile :
            raise Exception ("Invalid CAP file format (Not a valid ZIP)")

        return bytes (blob ),pkg_aid ,applet_aids 

    @staticmethod 
    def _extract_pkg_aid (data :bytes )->bytes :



        try :
            if len (data )>13 :
                aid_len =data [12 ]
                return data [13 :13 +aid_len ]
        except Exception :
            pass 

        return b''

    @staticmethod 
    def _extract_applet_aids (data :bytes )->List [bytes ]:


        aids =[]
        try :
            if len (data )>=4 :
                count =data [3 ]
                offset =4 
                for _ in range (count ):
                    if offset >=len (data ):
                        break 

                    aid_len =data [offset ]
                    offset +=1 

                    aid =data [offset :offset +aid_len ]
                    aids .append (aid )


                    offset +=aid_len +2 
        except Exception :
            pass 

        return aids 