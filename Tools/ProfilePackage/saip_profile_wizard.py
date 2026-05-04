"""
Tag-granular wizard for scaffolding a brand-new SAIP profile from a preset.

The wizard is split into single-responsibility steps so each can be unit
tested in isolation (per the YggdraSIM wizard rule: "All wizards shall be
split down into each nestled tag"). Step ordering:

  1. ``step_pick_preset``            - choose the base preset.
  2. ``step_customise_menu_ids``     - keep / drop each PE (optional).
  3. ``step_collect_placeholders``   - ICCID / IMSI prompts with AUTO support.
  4. ``step_pick_output_format``     - DER profile or JSON template.
  5. ``step_declare_tokens``         - JSON-only: declare __ygg_token_defs__.
  6. ``step_pick_output_path``       - absolute path or workspace default.
  7. ``step_confirm``                - review screen, abort / accept.

Callers instantiate :class:`NewProfileWizard` with an ``input_fn`` (defaults
to :func:`input`), an ``output_fn`` (defaults to ``print``), and a workspace
root. :meth:`run` returns a :class:`WizardDecision` describing what the
caller must materialise. The wizard never touches the filesystem itself;
all encoding / writing is delegated to the shell command that invoked it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from .saip_profile_scaffold import (
    default_preset_id,
    describe_preset,
    get_preset,
    list_preset_placeholders,
    list_profile_presets,
    normalize_preset_id,
)
from .saip_profile_randomizer import is_auto_sentinel
from .saip_token_sidecar import (
    parse_token_value_argument as _parse_token_value_argument,
)

import re

_TOKEN_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


InputFunction = Callable[[str], str]
OutputFunction = Callable[[str], None]


class WizardAborted(Exception):
    """Raised when the user backs out of the wizard."""


@dataclass
class WizardDecision:
    preset_id: str
    menu_ids: tuple[str, ...]
    placeholders: dict[str, str]
    output_format: str
    output_path: Path
    verify: bool = False
    token_defs: dict[str, object] = field(default_factory=dict)
    placeholder_style: str = "brace"


@dataclass
class _WizardState:
    preset_id: str = field(default_factory=default_preset_id)
    menu_ids: tuple[str, ...] = tuple()
    placeholders: dict[str, str] = field(default_factory=dict)
    output_format: str = "der"
    output_path: Optional[Path] = None
    verify: bool = False
    token_defs: dict[str, object] = field(default_factory=dict)
    placeholder_style: str = "brace"


class NewProfileWizard:
    def __init__(
        self,
        workspace_root: Path,
        *,
        default_output_dir: Path | None = None,
        input_fn: InputFunction | None = None,
        output_fn: OutputFunction | None = None,
        timestamp_fn: Callable[[], str] | None = None,
    ) -> None:
        self.workspace_root = Path(workspace_root)
        self.default_output_dir = Path(default_output_dir or self.workspace_root)
        self._input_fn = input_fn or input
        self._output_fn = output_fn or print
        self._timestamp_fn = timestamp_fn or _iso_compact_timestamp
        self._state = _WizardState()

    def run(self) -> WizardDecision:
        self.step_pick_preset()
        self.step_customise_menu_ids()
        self.step_collect_placeholders()
        self.step_pick_output_format()
        self.step_declare_tokens()
        self.step_pick_output_path()
        self.step_confirm()
        if self._state.output_path is None:
            raise RuntimeError("Wizard terminated without an output path.")
        return WizardDecision(
            preset_id=self._state.preset_id,
            menu_ids=self._state.menu_ids,
            placeholders=dict(self._state.placeholders),
            output_format=self._state.output_format,
            output_path=self._state.output_path,
            verify=self._state.verify,
            token_defs=dict(self._state.token_defs),
            placeholder_style=self._state.placeholder_style,
        )

    def step_pick_preset(self) -> None:
        self._emit("")
        self._emit("Step 1/7 -- Pick a base preset")
        presets = list_profile_presets()
        for index, preset in enumerate(presets, start=1):
            marker = ""
            if preset.preset_id == default_preset_id():
                marker = " (default)"
            tag = f" [{preset.source}]"
            if preset.source == "builtin":
                tag = ""
            self._emit(
                f"  {index}. {preset.preset_id}{marker}{tag} -- {preset.description}"
            )
        self._emit("")
        default_prompt = (
            f"Preset name or number [{default_preset_id()}]: "
        )
        raw = self._input_fn(default_prompt).strip()
        if len(raw) == 0:
            chosen_id = default_preset_id()
        elif raw.isdigit():
            chosen_index = int(raw)
            if chosen_index < 1 or chosen_index > len(presets):
                raise ValueError(
                    f"Preset selection {raw!r} out of range (1..{len(presets)})."
                )
            chosen_id = presets[chosen_index - 1].preset_id
        else:
            chosen_id = normalize_preset_id(raw)
        self._state.preset_id = chosen_id
        self._state.menu_ids = get_preset(chosen_id).menu_ids

    def step_customise_menu_ids(self) -> None:
        self._emit("")
        self._emit("Step 2/7 -- Review PE sequence")
        description = describe_preset(self._state.preset_id)
        for entry in description["pes"]:
            self._emit(f"  - {entry['menu_id']}: {entry['description']}")
        prompt = (
            "Drop any optional PEs? Enter comma-separated menu_ids to drop, "
            "or press enter to keep all: "
        )
        raw = self._input_fn(prompt).strip()
        if len(raw) == 0:
            return
        drop_tokens = {token.strip() for token in raw.split(",") if len(token.strip()) > 0}
        invalid_drops = drop_tokens - set(self._state.menu_ids)
        if len(invalid_drops) > 0:
            raise ValueError(
                f"Cannot drop menu_ids not present in preset: {sorted(invalid_drops)}"
            )
        forbidden_drops = drop_tokens & {"header", "end"}
        if len(forbidden_drops) > 0:
            raise ValueError(
                "Refusing to drop mandatory PEs: header and end must be present."
            )
        reduced = tuple(
            menu_id
            for menu_id in self._state.menu_ids
            if menu_id not in drop_tokens
        )
        self._state.menu_ids = reduced

    def step_collect_placeholders(self) -> None:
        self._emit("")
        self._emit("Step 3/7 -- Typed placeholder values (optional)")
        available = list_preset_placeholders(self._state.preset_id)
        if len(available) == 0:
            self._emit("  (no typed placeholders applicable to this preset)")
            return
        for placeholder_name in available:
            prompt = (
                f"  {placeholder_name} value, AUTO for random, or enter to skip: "
            )
            raw = self._input_fn(prompt).strip()
            if len(raw) == 0:
                continue
            self._state.placeholders[placeholder_name] = raw

    def step_pick_output_format(self) -> None:
        self._emit("")
        self._emit("Step 4/7 -- Output format")
        self._emit("  1. DER profile (.der)")
        self._emit("  2. JSON template (.json)")
        prompt = "Format [1=DER, 2=JSON, default 1]: "
        raw = self._input_fn(prompt).strip()
        if len(raw) == 0 or raw == "1" or raw.upper() in ("DER", "D"):
            self._state.output_format = "der"
            return
        if raw == "2" or raw.upper() in ("JSON", "J"):
            self._state.output_format = "json"
            return
        raise ValueError(
            f"Unknown output format {raw!r}. Use 1/DER or 2/JSON."
        )

    def step_declare_tokens(self) -> None:
        self._emit("")
        self._emit("Step 5/7 -- Declare template tokens (optional)")
        if self._state.output_format != "json":
            self._emit("  (skipped -- tokens only apply to JSON templates)")
            return
        self._emit(
            "  Template tokens become {NAME}/[NAME] placeholders in the "
            "output JSON."
        )
        self._emit(
            "  Enter a blank token name to finish. Style defaults to brace."
        )
        style_raw = self._input_fn(
            "  Placeholder style [brace/bracket, default brace]: "
        ).strip().lower()
        if style_raw in ("bracket", "brackets", "[", "[]"):
            self._state.placeholder_style = "bracket"
        else:
            self._state.placeholder_style = "brace"
        declared: dict[str, object] = {}
        while True:
            name_raw = self._input_fn(
                "  Token name (blank to finish): "
            ).strip()
            if len(name_raw) == 0:
                break
            if _TOKEN_NAME_RE.fullmatch(name_raw) is None:
                self._emit(
                    f"  [-] Invalid token name {name_raw!r}: "
                    "use [A-Za-z][A-Za-z0-9_]*."
                )
                continue
            if name_raw in declared:
                self._emit(
                    f"  [-] Token {name_raw} already declared; "
                    "re-enter to overwrite or press enter to skip."
                )
            value_raw = self._input_fn(
                f"  Value for {name_raw} "
                "(hex, {\"zero_len\":N}, or {\"pattern_hex\":..,\"byte_len\":N}): "
            ).strip()
            if len(value_raw) == 0:
                self._emit(
                    f"  [-] Skipping {name_raw}: empty value."
                )
                continue
            try:
                parsed = _parse_token_value_argument(value_raw)
            except Exception as error:
                self._emit(f"  [-] Rejected {name_raw}: {error}")
                continue
            declared[name_raw] = parsed
        self._state.token_defs = declared
        if len(declared) == 0:
            self._emit("  (no tokens declared)")
        else:
            for name in declared.keys():
                self._emit(f"    + {name}")

    def step_pick_output_path(self) -> None:
        self._emit("")
        self._emit("Step 6/7 -- Output file")
        default_path = self._build_default_output_path()
        prompt = (
            f"Path [{default_path}]: "
        )
        raw = self._input_fn(prompt).strip()
        if len(raw) == 0:
            self._state.output_path = default_path
            return
        candidate = Path(raw).expanduser()
        if candidate.is_absolute() is False:
            candidate = self.workspace_root / candidate
        self._state.output_path = candidate

    def step_confirm(self) -> None:
        self._emit("")
        self._emit("Step 7/7 -- Review")
        self._emit(f"  Preset:     {self._state.preset_id}")
        self._emit(f"  PEs:        {' -> '.join(self._state.menu_ids)}")
        if len(self._state.placeholders) == 0:
            self._emit("  Overrides:  (none)")
        else:
            self._emit("  Overrides:")
            for name, value in self._state.placeholders.items():
                display_value = value
                if is_auto_sentinel(value):
                    display_value = f"{value} (auto-generated)"
                self._emit(f"    {name} = {display_value}")
        self._emit(f"  Format:     {self._state.output_format.upper()}")
        if self._state.output_format == "json":
            if len(self._state.token_defs) == 0:
                self._emit("  Tokens:     (none)")
            else:
                self._emit(
                    f"  Tokens:     {len(self._state.token_defs)} "
                    f"(style={self._state.placeholder_style})"
                )
                for name in self._state.token_defs.keys():
                    self._emit(f"    • {name}")
        self._emit(f"  Output:     {self._state.output_path}")
        if self._state.output_format == "der":
            verify_raw = self._input_fn("Verify round-trip after write? [y/N]: ").strip()
            if verify_raw.upper() in ("Y", "YES"):
                self._state.verify = True
        confirm_raw = self._input_fn("Proceed? [Y/n]: ").strip()
        if len(confirm_raw) > 0 and confirm_raw.upper() not in ("Y", "YES"):
            raise WizardAborted("User declined the wizard summary.")

    def _build_default_output_path(self) -> Path:
        timestamp = self._timestamp_fn()
        suffix = ".der"
        if self._state.output_format == "json":
            suffix = ".json"
        filename = f"scaffold-{self._state.preset_id.lower()}-{timestamp}{suffix}"
        return self.default_output_dir / filename

    def _emit(self, message: str) -> None:
        self._output_fn(message)


def _iso_compact_timestamp() -> str:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%d-%H%M%S")


def resolve_default_scaffold_output_path(
    preset_id: str,
    extension: str,
    output_dir: Path,
    *,
    timestamp_fn: Callable[[], str] | None = None,
) -> Path:
    """
    Deterministic default path builder shared by the non-interactive commands.
    """
    timestamp_producer = timestamp_fn or _iso_compact_timestamp
    clean_extension = str(extension or "").strip().lower().lstrip(".")
    if clean_extension not in ("der", "json"):
        raise ValueError(
            f"Default scaffold output extension must be 'der' or 'json' (got {extension!r})."
        )
    stamp = timestamp_producer()
    filename = f"scaffold-{preset_id.lower()}-{stamp}.{clean_extension}"
    return Path(output_dir) / filename


def summarise_wizard_decision(decision: WizardDecision) -> Iterable[str]:
    yield f"preset={decision.preset_id}"
    yield f"format={decision.output_format.upper()}"
    yield f"output={decision.output_path}"
    if decision.verify is True:
        yield "verify=on"
    if len(decision.placeholders) > 0:
        placeholder_parts = [
            f"{name}={value}" for name, value in decision.placeholders.items()
        ]
        yield f"placeholders={{{', '.join(placeholder_parts)}}}"
