from typing import Any, Callable, Iterable, Optional, TypeVar


TagT = TypeVar("TagT")


def resolve_profile_target_identifier(
    identifier: str,
    *,
    tag_aid: TagT,
    tag_iccid: TagT,
    resolve_aid_from_alias: Callable[[str], Optional[str]],
    is_hex: Callable[[str], bool],
    extract_decimal_iccid: Callable[[str], Optional[str]],
    encode_iccid_for_command: Callable[[str], str],
    fetch_profiles: Callable[[], Iterable[Any]],
) -> Optional[tuple[TagT, str]]:
    clean = str(identifier or "").strip().upper()
    if len(clean) == 0:
        return None

    alias_match = resolve_aid_from_alias(clean)
    if alias_match is not None:
        return tag_aid, alias_match

    if is_hex(clean):
        if clean.startswith("A0") and len(clean) >= 10:
            return tag_aid, clean

    # fetch_profiles is an injected callable from each shell; a failing
    # backend should degrade to "no match" rather than crash the caller.
    try:
        profiles = list(fetch_profiles() or [])
    except (RuntimeError, OSError, ValueError, AttributeError, TypeError):
        profiles = []
    for row in profiles:
        iccid_value = str(getattr(row, "iccid", "") or "").strip().upper()
        aid_value = str(getattr(row, "aid", "") or "").strip().upper()
        if iccid_value == clean:
            return tag_iccid, encode_iccid_for_command(iccid_value)
        if aid_value == clean:
            return tag_aid, aid_value
        if len(iccid_value) == 0:
            continue
        encoded_iccid = encode_iccid_for_command(iccid_value).upper()
        if encoded_iccid == clean:
            return tag_iccid, encoded_iccid

    decimal_iccid = extract_decimal_iccid(clean)
    if decimal_iccid is not None:
        return tag_iccid, encode_iccid_for_command(decimal_iccid)

    if is_hex(clean):
        if len(clean) >= 18:
            return tag_iccid, clean

    return None
