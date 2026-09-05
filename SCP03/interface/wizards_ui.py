# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""Reusable terminal wizard with explicit validation and secret-safe input."""

from __future__ import annotations

import getpass
import re
from collections.abc import Callable, Iterable
from typing import Any


class InteractiveWizard:
    """Collect a sequence of terminal inputs.

    ``run`` returns ``None`` when the operator types ``CANCEL``/``ABORT``
    (optionally prefixed with ``/``), presses Ctrl-C, or reaches EOF.  Callers
    must treat that as a clean cancellation and avoid executing an operation.

    Legacy prompt-based hex detection remains available, but new call sites
    should set ``input_kind="hex"`` or ``input_kind="text"`` explicitly.
    """

    _CANCEL_WORDS = frozenset({"CANCEL", "/CANCEL", "ABORT", "/ABORT"})
    _YES_WORDS = frozenset({"Y", "YES", "TRUE", "1"})
    _NO_WORDS = frozenset({"N", "NO", "FALSE", "0"})

    def __init__(self, title, colors_ref, description=""):
        self.title = title
        self.description = description
        self.steps: list[dict[str, Any]] = []
        self.current_idx = 0
        self.results: dict[str, Any] = {}
        self.colors = colors_ref

    def add_step(
        self,
        step_id,
        prompt,
        default=None,
        is_bool=False,
        indent=0,
        warning=None,
        is_mandatory=False,
        condition=None,
        builder_func=None,
        *,
        input_kind: str | None = None,
        choices: Iterable[str] | None = None,
        secret: bool = False,
        validator: Callable[[Any], str | None] | None = None,
    ):
        """Append a wizard step.

        ``choices`` contains canonical accepted values and is matched
        case-insensitively. ``validator`` returns an error message or ``None``.
        Secret values are collected with :mod:`getpass` and never echoed.
        """
        if input_kind not in (None, "hex", "text"):
            raise ValueError("input_kind must be None, 'hex', or 'text'.")
        canonical_choices = None
        if choices is not None:
            canonical_choices = tuple(str(value) for value in choices)
            if not canonical_choices:
                raise ValueError("choices cannot be empty.")

        self.steps.append(
            {
                "id": step_id,
                "prompt": prompt,
                "default": default,
                "is_bool": is_bool,
                "indent": indent,
                "warning": warning,
                "is_mandatory": is_mandatory,
                "condition": condition,
                "builder_func": builder_func,
                "input_kind": input_kind,
                "choices": canonical_choices,
                "secret": bool(secret),
                "validator": validator,
                "value": None,
                "status": "pending",
            }
        )

    @staticmethod
    def _looks_like_hex_prompt(prompt: str | None) -> bool:
        """Retain conservative compatibility for older wizard definitions."""
        if prompt is None:
            return False
        prompt_l = prompt.lower()
        if "hex/name" in prompt_l or "hex or name" in prompt_l:
            return False
        if re.search(r"\b\d+\s*=", prompt_l) is not None:
            return False
        return "hex" in prompt_l

    @staticmethod
    def _normalize_hex_string(raw_val: str) -> str:
        cleaned = re.sub(r"[\s:_-]", "", str(raw_val).strip())
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if not cleaned or len(cleaned) % 2:
            raise ValueError(
                "Invalid hex string. Use an even number of hexadecimal digits."
            )
        try:
            bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError(
                "Invalid hex string. Use hexadecimal digits 0-9 and A-F only."
            ) from error
        return cleaned.upper()

    @staticmethod
    def _is_valid_hex_string(raw_val: str) -> bool:
        try:
            InteractiveWizard._normalize_hex_string(raw_val)
        except ValueError:
            return False
        return True

    @staticmethod
    def _canonical_choice(value: str, choices: tuple[str, ...]) -> str | None:
        folded = value.casefold()
        for candidate in choices:
            if candidate.casefold() == folded:
                return candidate
        return None

    def _render_completed_step(self, step) -> None:
        indent_str = "  " * step["indent"]
        prompt_text = step["prompt"]
        if step["status"] == "skipped":
            print(
                f"{indent_str}{self.colors.WARNING}> {prompt_text} "
                f"SKIPPED{self.colors.ENDC}"
            )
            return

        value = step["value"]
        if step["secret"]:
            val_str = "<hidden>"
        elif step["is_bool"]:
            val_str = "Y" if value else "N"
        else:
            val_str = str(value)

        color = self.colors.GREEN
        if step["status"] == "defaulted":
            color = self.colors.WARNING
        print(f"{indent_str}{color}> {prompt_text} {val_str}{self.colors.ENDC}")

    def _read(self, step, prompt_str: str) -> str:
        if step["secret"]:
            return getpass.getpass(prompt_str).strip()
        return input(prompt_str).strip()

    def _cancel(self) -> None:
        print(f"{self.colors.WARNING}[-] Wizard cancelled; no action taken.{self.colors.ENDC}")
        return None

    def _validate_value(self, step, value: Any) -> tuple[Any, str | None]:
        if step["is_mandatory"] and (
            value is None or value == "" or str(value).upper() == "SKIP"
        ):
            return value, "This field is mandatory and cannot be skipped."

        if value is None or value == "" or str(value).upper() == "SKIP":
            return value, None

        choices = step["choices"]
        if choices is not None:
            canonical = self._canonical_choice(str(value), choices)
            if canonical is None:
                return value, f"Choose one of: {', '.join(choices)}."
            value = canonical

        input_kind = step["input_kind"]
        if input_kind == "hex" or (
            input_kind is None and self._looks_like_hex_prompt(step["prompt"])
        ):
            try:
                value = self._normalize_hex_string(str(value))
            except ValueError as error:
                return value, str(error)

        validator = step["validator"]
        if validator is not None:
            try:
                error_message = validator(value)
            except (TypeError, ValueError) as error:
                error_message = str(error)
            if error_message:
                return value, str(error_message)

        return value, None

    def run(self):
        """Run the steps and return their values, or ``None`` on cancellation."""
        print(f"\n{self.colors.HEADER}--- {self.title} ---{self.colors.ENDC}")
        if self.description:
            print(f"{self.description}\n")
        print(
            f"{self.colors.CYAN}Type CANCEL at any prompt to abort safely."
            f"{self.colors.ENDC}"
        )

        while self.current_idx < len(self.steps):
            step = self.steps[self.current_idx]
            indent_str = "  " * step["indent"]

            if step["condition"] is not None and not step["condition"](self.results):
                step["status"] = "skipped"
                step["value"] = None
                self.results[step["id"]] = None
                self.current_idx += 1
                continue

            if step["warning"]:
                print(
                    f"{indent_str}{self.colors.WARNING}[!] "
                    f"{step['warning']}{self.colors.ENDC}"
                )

            prompt_str = (
                f"{indent_str}{self.colors.BOLD}> {step['prompt']}"
                f"{self.colors.ENDC} "
            )
            try:
                user_input = self._read(step, prompt_str)
            except (EOFError, KeyboardInterrupt):
                print("")
                return self._cancel()

            if user_input.upper() in self._CANCEL_WORDS:
                return self._cancel()

            status = "completed"
            if not user_input:
                value = step["default"]
                status = "defaulted" if value is not None else "skipped"
            elif step["is_bool"]:
                normalized = user_input.upper()
                if normalized in self._YES_WORDS:
                    value = True
                elif normalized in self._NO_WORDS:
                    value = False
                else:
                    print(
                        f"{indent_str}{self.colors.WARNING}[!] Enter Y/YES or "
                        f"N/NO.{self.colors.ENDC}"
                    )
                    continue
            elif user_input.upper() == "SKIP":
                value = "SKIP"
                status = "skipped"
            else:
                value = user_input

            if isinstance(value, str) and value.upper() == "SKIP":
                value = "SKIP"
                status = "skipped"

            value, error_message = self._validate_value(step, value)
            if error_message:
                print(
                    f"{indent_str}{self.colors.WARNING}[!] "
                    f"{error_message}{self.colors.ENDC}"
                )
                continue

            step["value"] = value
            step["status"] = status
            self.results[step["id"]] = value
            self.current_idx += 1
            self._render_completed_step(step)

            if (
                step["builder_func"] is not None
                and step["is_bool"]
                and step["value"] is True
            ):
                built_val = step["builder_func"]()
                if built_val is None:
                    return None
                self.results[step["id"] + "_built"] = built_val

        return self.results
