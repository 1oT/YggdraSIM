import os

class Config:
    """Centralized configuration and constants."""
    # Paths are relative to this file location
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    INI_FILE = os.path.join(BASE_DIR, 'keys.ini')
    FIDS_FILE = os.path.join(BASE_DIR, 'fids.txt')
    AID_FILE = os.path.join(BASE_DIR, 'aid.txt')

    DEFAULT_KEYS = {
        'kenc': '1122334455667788AABBCCDDEEFF0011',
        'kmac': '1122334455667788AABBCCDDEEFF0011',
        'kvn': '30',
        'aid': 'A0000005591010FFFFFFFF8900000100',
        'adm': '0000000000000000'
    }

    class Colors:
        HEADER = '\033[95m' # Purple
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        RED = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        WHITE = '\033[97m'