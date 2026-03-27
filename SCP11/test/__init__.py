__all__ = [
    "SGPConfig",
    "SGP22Orchestrator",
]


def __getattr__(name):
    if name == "SGPConfig":
        from .config import SGPConfig
        return SGPConfig
    if name == "SGP22Orchestrator":
        from .orchestrator import SGP22Orchestrator
        return SGP22Orchestrator
    raise AttributeError(name)
