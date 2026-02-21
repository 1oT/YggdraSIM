# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import zipfile
import os
from typing import Tuple, List, Optional

class CapFileParser:
    # Standard Java Card Component Order for the Load File
    ORDER = [
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
        'Descriptor.cap' # Optional
    ]

    @staticmethod
    def parse(cap_path: str) -> Tuple[bytes, bytes, List[bytes]]:
        """
        Parses a CAP (Zip) or IJC (Raw) file.
        Returns: (LoadFileBlock, PackageAID, List[AppletAIDs])
        """
        if not os.path.exists(cap_path):
            raise FileNotFoundError(f"File not found: {cap_path}")

        if cap_path.lower().endswith('.ijc'):
            return CapFileParser._parse_ijc(cap_path)
        else:
            return CapFileParser._parse_cap(cap_path)

    @staticmethod
    def _parse_ijc(ijc_path: str) -> Tuple[bytes, bytes, List[bytes]]:
        """
        Parses a pre-arranged .ijc file directly.
        Iterates over the component tags to extract metadata.
        """
        with open(ijc_path, 'rb') as f:
            data = f.read()

        pkg_aid = b''
        applet_aids = []
        offset = 0
        data_len = len(data)

        # Java Card Component Format: [Tag (1 byte)] [Size (2 bytes)] [Info (Size bytes)]
        while offset < data_len:
            if offset + 3 > data_len:
                break
                
            tag = data[offset]
            size = int.from_bytes(data[offset+1 : offset+3], byteorder='big')
            comp_data = data[offset : offset + 3 + size]
            
            if tag == 1:
                # Tag 1 is the Header Component
                pkg_aid = CapFileParser._extract_pkg_aid(comp_data)
            elif tag == 3:
                # Tag 3 is the Applet Component
                applet_aids = CapFileParser._extract_applet_aids(comp_data)
                
            offset += 3 + size

        return data, pkg_aid, applet_aids

    @staticmethod
    def _parse_cap(cap_path: str) -> Tuple[bytes, bytes, List[bytes]]:
        """
        Parses a standard .cap ZIP archive file.
        Extracts, orders, and concatenates the internal .cap components.
        """
        blob = bytearray()
        pkg_aid = b''
        applet_aids = []

        try:
            with zipfile.ZipFile(cap_path, 'r') as z:
                # 1. Map base names to full paths (handle subfolders like javacard/framework/...)
                all_files = z.namelist()
                component_map = {}
                for f in all_files:
                    if f.lower().endswith('.cap'):
                        base = os.path.basename(f)
                        component_map[base] = f

                # 2. Concatenate Components in Order
                for comp_name in CapFileParser.ORDER:
                    if comp_name in component_map:
                        path = component_map[comp_name]
                        data = z.read(path)
                        blob.extend(data)
                        
                        # 3. Extract Metadata on the fly
                        if comp_name == 'Header.cap':
                            pkg_aid = CapFileParser._extract_pkg_aid(data)
                        elif comp_name == 'Applet.cap':
                            applet_aids = CapFileParser._extract_applet_aids(data)

        except zipfile.BadZipFile:
            raise Exception("Invalid CAP file format (Not a valid ZIP)")
            
        return bytes(blob), pkg_aid, applet_aids

    @staticmethod
    def _extract_pkg_aid(data: bytes) -> bytes:
        # Header Component: [Tag=1] [Size=2] [Magic=4] [Minor=1] [Major=1] [Flags=1] [PkgInfo]
        # PkgInfo starts at index 10: [Minor=1] [Major=1] [AID_Len=1] [AID]
        # Therefore, AID_Len is at index 12, and AID starts at 13.
        try:
            if len(data) > 13:
                aid_len = data[12]
                return data[13 : 13 + aid_len]
        except Exception:
            pass
            
        return b''

    @staticmethod
    def _extract_applet_aids(data: bytes) -> List[bytes]:
        # Applet Component: [Tag=3] [Size=2] [Count=1] [Applet1] [Applet2]...
        # AppletX: [AID_Len=1] [AID] [Install_Method_Offset=2]
        aids = []
        try:
            if len(data) >= 4:
                count = data[3]
                offset = 4
                for _ in range(count):
                    if offset >= len(data):
                        break
                        
                    aid_len = data[offset]
                    offset += 1
                    
                    aid = data[offset : offset + aid_len]
                    aids.append(aid)
                    
                    # Skip AID + Install Offset (2 bytes) to reach the next applet
                    offset += aid_len + 2
        except Exception:
            pass
            
        return aids