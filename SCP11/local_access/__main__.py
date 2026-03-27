from .main import entry
from yggdrasim_common.quit_control import QuitAllRequested


if __name__ == "__main__":
    try:
        entry()
    except QuitAllRequested:
        raise SystemExit(0)
