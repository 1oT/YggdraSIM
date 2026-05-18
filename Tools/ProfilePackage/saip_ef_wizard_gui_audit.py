# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Cross-checks simulator ``_FILE_SPECS`` against Command Center EF wizards.

``yggdrasim_common/gui_server/static/app.js`` registers dedicated transparent
wizards in ``_SAIP_WIZARDS`` and record-fixed wizards in ``_SAIP_RECORD_WIZARDS``.
``saipRenderEfWizardCard`` / per-record rendering fall back to generic hex
wizards when no dedicated entry exists, so every EF still has a wizard-shaped
edit path.

This module parses the shipped ``app.js`` and answers:

* whether every **dedicated** wizard key is backed by ``_FILE_SPECS`` (or is
  an explicitly documented orphan spelling);
* whether **FID anchors** shared between ``Tools/ProfilePackage/saip_asn1_decode``
  and ``_FILE_SPECS`` stay aligned where both sides carry a non-empty FID.

Run::

    python3 -m Tools.ProfilePackage.saip_ef_wizard_gui_audit
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"


def normalize_ef_gui_key(raw: str) -> str:
    return str(raw or "").strip().lower().replace("_", "-")


def _extract_braced_block(text: str, marker: str) -> str | None:
    start = text.find(marker)
    if start < 0:
        return None
    open_brace = text.find("{", start)
    if open_brace < 0:
        return None
    depth = 0
    j = open_brace
    while j < len(text):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : j]
        j += 1
    return None


def parse_saip_wizard_ef_keys(app_js: str) -> frozenset[str]:
    """Union of ``_SAIP_WIZARDS`` map keys (initial literal + bracket assigns)."""
    keys: set[str] = set()
    block = _extract_braced_block(app_js, "var _SAIP_WIZARDS = {")
    if block is not None:
        for match in re.finditer(r"\"(ef-[a-z0-9-]+)\"\s*:", block):
            keys.add(normalize_ef_gui_key(match.group(1)))
    assign_re = re.compile(r"_SAIP_WIZARDS\s*\[\s*[\"']([^\"']+)[\"']\s*\]\s*=")
    for match in assign_re.finditer(app_js):
        keys.add(normalize_ef_gui_key(match.group(1)))
    return frozenset(k for k in keys if k.startswith("ef-"))


def parse_saip_record_wizard_ef_keys(app_js: str) -> frozenset[str]:
    keys: set[str] = set()
    block = _extract_braced_block(app_js, "var _SAIP_RECORD_WIZARDS = {")
    if block is not None:
        for match in re.finditer(r"\"(ef-[a-z0-9-]+)\"\s*:", block):
            keys.add(normalize_ef_gui_key(match.group(1)))
    assign_re = re.compile(r"_SAIP_RECORD_WIZARDS\s*\[\s*[\"']([^\"']+)[\"']\s*\]\s*=")
    for match in assign_re.finditer(app_js):
        k = normalize_ef_gui_key(match.group(1))
        if k.startswith("ef-"):
            keys.add(k)
    return frozenset(keys)


# Dedicated transparent keys present in ``app.js`` without a matching
# ``_FILE_SPECS`` row after underscore/dash normalisation. Each entry is a
# deliberate spelling variant, synonym path, or catalogue-only token.
_EF_WIZARD_ORPHAN_TRANSPARENT_KEYS: frozenset[str] = frozenset(
    {
        "ef-hplmn-wact",
        "ef-acmmax",
        "ef-supi-nai",
        "ef-5gs3gppguti",
        "ef-5gsn3gppguti",
        "ef-gba",
        "ef-pscoi",
    },
)


def file_spec_normalized_keys() -> frozenset[str]:
    from SIMCARD.saip_profile import _FILE_SPECS

    return frozenset(normalize_ef_gui_key(k) for k in _FILE_SPECS)


def dedicated_wizard_keys_subset_of_specs_or_orphans(app_js: str | None = None) -> list[str]:
    """Return orphan dedicated wizard keys (violations). Empty when healthy."""
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    specs = file_spec_normalized_keys()
    bad: list[str] = []
    for key in sorted(parse_saip_wizard_ef_keys(text)):
        if key in specs or key in _EF_WIZARD_ORPHAN_TRANSPARENT_KEYS:
            continue
        bad.append(key)
    return bad


def record_wizard_keys_subset_of_specs_or_orphans(app_js: str | None = None) -> list[str]:
    """Return record-wizard keys that are not backed by ``_FILE_SPECS``."""
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    specs = file_spec_normalized_keys()
    orphans = frozenset({"ef-ext1", "ef-ext2", "ef-ext3", "ef-ext4", "ef-ext5"})
    bad: list[str] = []
    for key in sorted(parse_saip_record_wizard_ef_keys(text)):
        if key in specs or key in orphans:
            continue
        bad.append(key)
    return bad


# ``ef-arr`` is anchored at 2F06 on the MF in ``_FILE_SPECS`` while the
# ASN.1 token map also routes USIM-local ARR (6F06) through the same key
# name. Cross-checking a single FID pair would be misleading.
_EF_FID_CROSSCHECK_SKIP: frozenset[str] = frozenset({"ef-arr"})


def ef_fid_mismatches_ef_key_to_fid_vs_file_specs() -> list[tuple[str, str, str]]:
    """Return ``(ef_key, asn1_fid, spec_fid)`` tuples where FIDs disagree."""
    from SIMCARD.saip_profile import _FILE_SPECS
    from Tools.ProfilePackage.saip_asn1_decode import _EF_KEY_TO_FID

    out: list[tuple[str, str, str]] = []
    for raw_key, spec in _FILE_SPECS.items():
        k = normalize_ef_gui_key(raw_key)
        if not k.startswith("ef-"):
            continue
        if k in _EF_FID_CROSSCHECK_SKIP:
            continue
        spec_fid = str(spec.get("fid") or "").strip().upper()
        if len(spec_fid) == 0:
            continue
        asn_fid = str(_EF_KEY_TO_FID.get(k, "")).strip().upper()
        if len(asn_fid) == 0:
            continue
        if asn_fid != spec_fid:
            out.append((k, asn_fid, spec_fid))
    return out


def parse_saip_pe_registry_keys(app_js: str | None = None) -> frozenset[str]:
    """Literal keys from ``SAIP_PE_REGISTRY`` (before ``saipPeRegistryEntry`` fallbacks)."""
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    block = _extract_braced_block(text, "var SAIP_PE_REGISTRY = {")
    if block is None:
        return frozenset()
    keys: set[str] = set()
    for match in re.finditer(
        r"(?:^|\n)\s*(?:\"([^\"]+)\"|([A-Za-z][A-Za-z0-9_]*))\s*:\s*\{\s*glyph",
        block,
        re.MULTILINE,
    ):
        token = match.group(1) or match.group(2)
        if token is not None and len(str(token).strip()) > 0:
            keys.add(str(token).strip())
    return frozenset(keys)


def pe_registry_gaps_for_known_union(app_js: str | None = None) -> list[str]:
    """PE bases that rely solely on the ``df-`` / ``adf-`` / default fallbacks."""
    from Tools.ProfilePackage.saip_pe_gui_gap import known_pe_types_union

    reg = {k.lower() for k in parse_saip_pe_registry_keys(app_js)}
    reg_nd = {k.replace("-", "").lower() for k in parse_saip_pe_registry_keys(app_js)}
    gaps: list[str] = []
    for pe in sorted(known_pe_types_union()):
        lo = pe.lower()
        if lo.startswith("df-") or lo.startswith("adf-"):
            continue
        if lo in reg:
            continue
        nd = lo.replace("-", "")
        if nd in reg_nd:
            continue
        gaps.append(pe)
    return gaps


def duplicate_wizard_assignments(app_js: str | None = None) -> list[str]:
    """Detect the same bracket key assigned twice (merge regressions)."""
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    counts: dict[str, int] = {}
    assign_re = re.compile(r"_SAIP_WIZARDS\s*\[\s*[\"']([^\"']+)[\"']\s*\]\s*=")
    for match in assign_re.finditer(text):
        k = normalize_ef_gui_key(match.group(1))
        counts[k] = counts.get(k, 0) + 1
    return sorted(k for k, n in counts.items() if n > 1)


# ---------------------------------------------------------------------------
# PE / EF decoded-edit coverage gap helpers.
#
# The GUI guarantees that every PE has a decoded-edit surface and every EF
# has either a typed wizard, a record wizard, or a dispatcher-emitted
# decoded payload that the per-record / per-EF generic decoded-edit panel
# can mutate. Both helpers must return the empty list in healthy state;
# CI gates them at zero in tests/test_saip_ef_wizard_five_sweeps.py.
# ---------------------------------------------------------------------------


def _ef_keys_known_to_dispatcher() -> frozenset[str]:
    from Tools.ProfilePackage.saip_asn1_decode import known_dispatcher_ef_keys

    return known_dispatcher_ef_keys()


def _ef_keys_with_any_wizard(app_js: str | None = None) -> frozenset[str]:
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    keys: set[str] = set()
    keys.update(parse_saip_wizard_ef_keys(text))
    keys.update(parse_saip_record_wizard_ef_keys(text))
    return frozenset(keys)


def ef_decoded_edit_coverage_gaps(app_js: str | None = None) -> list[str]:
    """Return ef-keys present in ``_FILE_SPECS`` with no edit surface.

    A key is "covered" when at least one of the following holds:

    * the dispatcher routes it (``_decode_known_ef_payload`` returns a
      populated decoded dict — drives the per-record / per-EF generic
      decoded-edit panel);
    * a dedicated transparent wizard is registered in ``_SAIP_WIZARDS``;
    * a dedicated record wizard is registered in ``_SAIP_RECORD_WIZARDS``;
    * ``_decode_ef_*`` opaque-passthrough catalog has the key (the panel
      still mounts on the ``decoded`` payload — opaque-annotated, but
      JSON-shaped).

    Returns the sorted list of orphan keys; expected to be empty.
    """

    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    specs = file_spec_normalized_keys()
    dispatcher_keys = _ef_keys_known_to_dispatcher()
    wizard_keys = _ef_keys_with_any_wizard(text)
    from Tools.ProfilePackage.saip_asn1_decode import (
        _OPAQUE_PASSTHROUGH_EF_CATALOG,
        dispatcher_routes_ef_key,
    )
    opaque_keys = frozenset(
        normalize_ef_gui_key(k) for k in _OPAQUE_PASSTHROUGH_EF_CATALOG
    )
    out: list[str] = []
    for key in sorted(specs):
        if key in dispatcher_keys:
            continue
        if dispatcher_routes_ef_key(key):
            continue
        if key in wizard_keys:
            continue
        if key in opaque_keys:
            continue
        out.append(key)
    return out


def ef_dispatcher_key_gaps() -> list[str]:
    """Return ``_FILE_SPECS`` ef-keys not accepted by the decoder dispatcher.

    This is stricter than decoded-edit coverage: a key may still be
    editable through a GUI wizard, but ``saip.show_file`` should be able
    to pass the canonical normalised key into
    ``_decode_known_ef_payload`` without relying on FID-only fallback.
    The check catches spelling drift such as ``ef-keysPS`` vs
    ``ef-keysps`` and dynamic token sets that were not exported through
    ``known_dispatcher_ef_keys()``.
    """

    from Tools.ProfilePackage.saip_asn1_decode import dispatcher_routes_ef_key

    return sorted(
        key
        for key in file_spec_normalized_keys()
        if key.startswith("ef-") and not dispatcher_routes_ef_key(key)
    )


# Default ``supportsDecodedPanel`` is true for every PE; the file-bearing
# templates opt out because their per-EF panel already carries the same
# fields. The GUI dispatch keeps these PEs hooked to typed editors. Any PE
# in this set MUST have a typed branch in the JS dispatch (``saipEditorRender*``
# / ``SAIP_PE_REGISTRY``); otherwise it would land at the untyped fallback
# WITHOUT a decoded panel, leaving operators without an edit surface.
_PE_DECODED_PANEL_OPTOUTS: frozenset[str] = frozenset(
    {
        "usim",
        "opt-usim",
        "optusim",
        "isim",
        "opt-isim",
        "optisim",
        "csim",
        "opt-csim",
        "optcsim",
        "mf",
        "telecom",
        "df-telecom",
        "phonebook",
        "df-phonebook",
        "df-5gs",
        "df-saip",
        "df-snpn",
        "df-5gprose",
        "df-eap",
        "df-tetra",
        "df-wlan",
        "gsm-access",
        "cd",
        "wlan",
        "umts",
        "iot",
        "opt-iot",
    },
)


def pe_decoded_edit_coverage_gaps(app_js: str | None = None) -> list[str]:
    """Return PE bases that have neither a typed editor nor the generic panel.

    A PE is "covered" when at least one of the following holds:

    * a typed branch in the JS dispatch handles its base name (matched
      via ``SAIP_PE_REGISTRY`` literal keys after the same normalisation
      ``saipPeFriendlyName`` uses);
    * it is NOT in the explicit ``supportsDecodedPanel = false`` opt-out
      set (which means the generic ``saipRenderDecodedEditPanel`` fires
      from the PE detail render path with ``fieldPath="*"``).

    Returns the sorted list of orphan PE bases; expected to be empty.
    """

    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    from Tools.ProfilePackage.saip_pe_gui_gap import known_pe_types_union

    registry = {k.lower() for k in parse_saip_pe_registry_keys(text)}
    registry_nodash = {k.replace("-", "").lower() for k in registry}
    out: list[str] = []
    for pe in sorted(known_pe_types_union()):
        lo = pe.lower()
        if lo.startswith("df-") or lo.startswith("adf-"):
            # DF / ADF templates don't ship as standalone editable PEs.
            continue
        if lo in registry or lo.replace("-", "") in registry_nodash:
            continue
        if lo in _PE_DECODED_PANEL_OPTOUTS:
            # Opt-out PE without a typed editor — coverage gap.
            out.append(pe)
            continue
        # Any other PE rides the default ``supportsDecodedPanel = true``
        # path — covered by the per-PE generic decoded panel.
    return out


def main() -> int:
    v1 = dedicated_wizard_keys_subset_of_specs_or_orphans()
    v2 = record_wizard_keys_subset_of_specs_or_orphans()
    v3 = ef_fid_mismatches_ef_key_to_fid_vs_file_specs()
    v4 = pe_registry_gaps_for_known_union()
    v5 = duplicate_wizard_assignments()
    v6 = ef_decoded_edit_coverage_gaps()
    v7 = pe_decoded_edit_coverage_gaps()
    v8 = ef_dispatcher_key_gaps()
    lines = [
        "dedicated wizard orphans (expect []): " + repr(v1),
        "record wizard orphans (expect []): " + repr(v2),
        "FID mismatches (expect []): " + repr(v3),
        "PE registry gaps vs union (informational): " + repr(v4),
        "duplicate _SAIP_WIZARDS assigns (expect []): " + repr(v5),
        "EF decoded-edit coverage gaps (expect []): " + repr(v6),
        "PE decoded-edit coverage gaps (expect []): " + repr(v7),
        "EF dispatcher key gaps (expect []): " + repr(v8),
    ]
    backlog = typed_wizard_backlog_by_wave()
    lines.append("typed-wizard backlog by wave (informational):")
    for wave_name in sorted(backlog):
        wave_items = backlog[wave_name]
        if len(wave_items) == 0:
            continue
        lines.append(
            "  - "
            + wave_name
            + " ("
            + str(len(wave_items))
            + "): "
            + ", ".join(wave_items[:8])
            + (", \u2026" if len(wave_items) > 8 else ""),
        )
    sys.stdout.write("\n".join(lines) + "\n")
    if (
        len(v1) > 0
        or len(v2) > 0
        or len(v3) > 0
        or len(v5) > 0
        or len(v6) > 0
        or len(v7) > 0
        or len(v8) > 0
    ):
        return 1
    return 0


# ---------------------------------------------------------------------------
# Typed-wizard backlog — informational only.
#
# Typed-wizard upgrades land in waves rather than a single big-bang.
# ``typed_wizard_backlog_by_wave()`` emits the current list of ef-keys
# that ride the generic decoded-edit panel, grouped by wave label.
# Each wave is a candidate PR; the helper is read
# by the audit ``main()`` for human-readable output and is NOT
# CI-gated. The generic panel covers each entry meanwhile, so a ``[]``
# is not required.
# ---------------------------------------------------------------------------


_TYPED_WIZARD_WAVE_BUCKETS: dict[str, frozenset[str]] = {
    "wave-A-usim-core": frozenset(
        {
            "ef-imsi",
            "ef-spn",
            "ef-ust",
            "ef-ad",
            "ef-ecc",
            "ef-acc",
            "ef-loci",
            "ef-msisdn",
            "ef-opl",
            "ef-pnn",
            "ef-hplmnwact",
            "ef-oplmnwact",
            "ef-fplmn",
            "ef-ehplmn",
            "ef-start-hfn",
            "ef-smsp",
            "ef-smss",
        },
    ),
    "wave-B-isim": frozenset(
        {
            "ef-impi",
            "ef-impu",
            "ef-domain",
            "ef-ist",
            "ef-pcscf",
            "ef-uicciari",
            "ef-gbabp",
            "ef-nafkca",
        },
    ),
    "wave-C-euicc": frozenset(
        {
            # ISD-R / ISD-P live in the SecurityDomain editor today;
            # bespoke euicc-specific wizards for the SGP.22 keysets and
            # certificate slots are deferred.
        },
    ),
    "wave-D-gfm": frozenset(
        {
            # Generic File Management already has a dedicated PE-level
            # wizard; the deferred slice is per-DGI sub-record editing
            # for DGI 0x1F00 / 0x6F1F batches.
        },
    ),
}


def typed_wizard_backlog_by_wave(
    app_js: str | None = None,
) -> dict[str, list[str]]:
    """Return ef-keys per backlog wave that still rely on the generic panel.

    Output keys map wave names (e.g. ``"wave-A-usim-core"``) to sorted
    lists of ef-key tokens that:

    * are listed in the wave bucket above;
    * are present in ``_FILE_SPECS`` (truth set anchor);
    * do NOT have a dedicated transparent or record wizard registered
      in ``app.js``.

    Wave buckets without remaining items are omitted from the result.
    """

    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    specs = file_spec_normalized_keys()
    have = _ef_keys_with_any_wizard(text)
    out: dict[str, list[str]] = {}
    for wave_name, bucket in _TYPED_WIZARD_WAVE_BUCKETS.items():
        remaining = sorted(
            key
            for key in bucket
            if key in specs and key not in have
        )
        if len(remaining) == 0:
            continue
        out[wave_name] = remaining
    return out


if __name__ == "__main__":
    raise SystemExit(main())
