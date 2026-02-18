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
        Parses a CAP (Zip) file.
        Returns: (LoadFileBlock, PackageAID, List[AppletAIDs])
        """
        if not os.path.exists(cap_path):
            raise FileNotFoundError(f"CAP file not found: {cap_path}")

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
        # Header Component: [Tag=1] [Size] [Magic] [Minor] [Major] [Flags] [PkgInfo]
        # PkgInfo: [Tag=1] [Size] [AID_Len] [AID] ...
        try:
            # Skip fixed header part (Tag(1)+Size(2)+Magic(4)+Ver(2)+Flags(1) = 10 bytes)
            # Actually, let's just scan for the PkgInfo tag (01) after the first few bytes
            # Heuristic: The AID is at index 13
            # Index 12 is AID Length
            if len(data) > 13:
                aid_len = data[12]
                return data[13 : 13+aid_len]
        except: pass
        return b''

    @staticmethod
    def _extract_applet_aids(data: bytes) -> List[bytes]:
        # Applet Component: [Tag=3] [Size] [Count] [Applet1] [Applet2]...
        # AppletX: [AID_Len] [AID] [Install_Method_Offset(2)]
        aids = []
        try:
            if len(data) < 4: return []
            count = data[3]
            offset = 4
            for _ in range(count):
                if offset >= len(data): break
                aid_len = data[offset]
                offset += 1
                aid = data[offset : offset + aid_len]
                aids.append(aid)
                offset += aid_len + 2 # Skip AID + Install Offset
        except: pass
        return aids