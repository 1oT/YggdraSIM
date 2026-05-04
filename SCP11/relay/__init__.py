__all__ = [
    "SCP11StartupError",
    "SGP22Client",
    "SGP22Orchestrator",
    "SGPConfig",
]


def __getattr__(name):
    if name == "SGPConfig":
        from .config import SGPConfig
        return SGPConfig
    if name == "SGP22Orchestrator":
        from .orchestrator import SGP22Orchestrator
        return SGP22Orchestrator
    if name == "SCP11StartupError":
        from .main import SCP11StartupError
        return SCP11StartupError
    if name == "SGP22Client":
        from .main import SGP22Client
        return SGP22Client
    raise AttributeError(name)
