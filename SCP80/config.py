# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import sys
import os
from pathlib import Path
from configparser import ConfigParser

class ConfigManager:
    DEFAULTS = {
        "cntr": "0000000001",
        "header": "447FF600000000000000",
        "payload": "",
        "spi": "1621",
        "kic": "15",
        "kid": "15",
        "tar": "B00000",
        "key_enc": "1111111111111111",
        "key_mac": "1111111111111111",
        "cla": "80",
        "transport": "print",
        "reader_idx": "0",
        "sender": "82",
    }

    def __init__(self):
        self.file_path = self._resolve_config_path()
        self.data = self.DEFAULTS.copy()
        self.load()

    def _resolve_config_path(self) -> Path:
        if getattr(sys, 'frozen', False):
            base = Path(sys.executable).parent
        else:
            base = Path(__file__).resolve().parent
        return base / "ota_config.ini"

    def load(self):
        if not self.file_path.exists(): return
        parser = ConfigParser()
        parser.read(self.file_path)
        if "ota" in parser:
            for k, v in parser["ota"].items():
                if k in self.data: self.data[k] = v

    def save(self):
        parser = ConfigParser()
        parser["ota"] = {k: str(v) for k, v in self.data.items()}
        with open(self.file_path, "w") as f: parser.write(f)

    def get(self, key: str) -> str:
        return self.data.get(key, self.DEFAULTS.get(key, ""))

    def set(self, key: str, value: str):
        if key in self.data:
            self.data[key] = value.replace(" ", "").strip() if key not in ["transport"] else value

    def get_int(self, key: str) -> int:
        try: return int(self.data.get(key, "0"), 10)
        except ValueError: return 0
    
    def increment_counter(self):
        try:
            val = int(self.data["cntr"], 16)
            val = (val + 1) & 0xFFFFFFFFFF
            self.data["cntr"] = f"{val:010X}"
            self.save()
        except ValueError:
            self.data["cntr"] = "0000000001"
            self.save()