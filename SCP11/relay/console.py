try:
    from ..console import SCP11Console
except ImportError:
    from SCP11.console import SCP11Console

__all__ = ["SCP11Console"]
