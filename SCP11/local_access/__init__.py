__all__ = [
    "LocalAccessConfig",
    "LocalIsdrSession",
    "LocalSessionState",
    "OpenSessionResult",
    "build_store_metadata_request_payload",
    "encode_store_metadata_request",
    "encode_store_metadata_request_from_file",
    "load_metadata_json_document",
]


def __getattr__(name):
    if name == "LocalAccessConfig":
        from .config import LocalAccessConfig
        return LocalAccessConfig
    if name in ("LocalIsdrSession", "LocalSessionState", "OpenSessionResult"):
        from .session import LocalIsdrSession, LocalSessionState, OpenSessionResult
        mapping = {
            "LocalIsdrSession": LocalIsdrSession,
            "LocalSessionState": LocalSessionState,
            "OpenSessionResult": OpenSessionResult,
        }
        return mapping[name]
    if name in (
        "build_store_metadata_request_payload",
        "encode_store_metadata_request",
        "encode_store_metadata_request_from_file",
        "load_metadata_json_document",
    ):
        from .metadata_codec import (
            build_store_metadata_request_payload,
            encode_store_metadata_request,
            encode_store_metadata_request_from_file,
            load_metadata_json_document,
        )
        mapping = {
            "build_store_metadata_request_payload": build_store_metadata_request_payload,
            "encode_store_metadata_request": encode_store_metadata_request,
            "encode_store_metadata_request_from_file": encode_store_metadata_request_from_file,
            "load_metadata_json_document": load_metadata_json_document,
        }
        return mapping[name]
    raise AttributeError(name)
