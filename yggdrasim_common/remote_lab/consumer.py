# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Card consumers: a HIL supervisor bound to one reserved modem rig.

A card rig serves the card it holds. A modem rig has no card, so the
operator offers one at reservation time and the rig consumes it. This
module owns the process that does the consuming, and the two rules that
make spawning it from a reservation defensible:

* The executable and every flag that is not derived from the offer come
  from rig config, never from the request. A reservation chooses which
  configured rig to start, not what to run.
* The offer's bearer token reaches the child as a ``0600`` file path and
  is never logged, echoed back, or placed on a command line, because a
  command line is readable by every process on the host.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from yggdrasim_common.card_bridge_auth import (
    default_token_file_for_port,
    write_token_file,
)
from yggdrasim_common.runtime_paths import ensure_runtime_dir, runtime_path

from .config import RigConfig

_LOGGER = logging.getLogger("yggdrasim.remote_lab.consumer")

# How long a stopped child gets to exit before it is killed outright.
CONSUMER_TERMINATION_TIMEOUT_SECONDS = 5.0
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)


class CardOfferError(ValueError):
    """Raised when an offered card cannot be accepted as given."""


@dataclass(frozen=True, slots=True)
class CardOffer:
    """A card the operator offers to a modem rig for one session."""

    url: str
    token: str = ""

    def redacted(self) -> dict[str, Any]:
        """The offer as it may be logged or returned: URL only."""
        return {"url": self.url, "transport": "http-card-bridge"}

    @classmethod
    def from_payload(cls, payload: Any) -> CardOffer:
        """Build an offer from a reservation body, or raise.

        The URL is the only operator-supplied value that reaches a
        subprocess argument list, so it is validated to be an ordinary
        http(s) URL with a host and nothing else attached.
        """
        if isinstance(payload, dict) is False:
            raise CardOfferError("card_offer must be a JSON object")
        url = str(payload.get("url") or "").strip()
        if len(url) == 0:
            raise CardOfferError("card_offer.url is required for a modem rig")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise CardOfferError("card_offer.url must be an http or https URL")
        if len(parsed.hostname or "") == 0:
            raise CardOfferError("card_offer.url must name a host")
        if len(parsed.query) > 0 or len(parsed.fragment) > 0:
            raise CardOfferError(
                "card_offer.url must carry no query string or fragment"
            )
        if parsed.username is not None or parsed.password is not None:
            raise CardOfferError("card_offer.url must carry no credentials")
        if url.endswith("/apdu") is False:
            url = url.rstrip("/") + "/apdu"
        return cls(url=url, token=str(payload.get("token") or "").strip())


def resolve_local_card_token(url: str, *, token_file: str = "") -> str:
    """Find the bearer token for a Card Bridge running on this machine.

    An operator offering their own card should not have to paste a token
    they never chose: ``yggdrasim-card-bridge`` writes one per port on
    startup, so the port in the offered URL names the file to read.
    """
    explicit = str(token_file or "").strip()
    if len(explicit) > 0:
        try:
            return Path(explicit).expanduser().read_text(encoding="utf-8").strip()
        except OSError as read_error:
            raise CardOfferError(
                f"Cannot read the card token file {explicit}: {read_error}"
            ) from read_error
    parsed = urlsplit(str(url or "").strip())
    port = parsed.port
    if port is None:
        return ""
    try:
        return default_token_file_for_port(int(port)).read_text(
            encoding="utf-8"
        ).strip()
    except OSError:
        return ""


def consumer_token_path(rig_id: str) -> str:
    """Where a rig's offered-card token is staged for its child process."""
    safe = "".join(
        character if character.isalnum() or character in "-_" else "_"
        for character in str(rig_id or "rig")
    )
    return runtime_path("state", f"remote_lab_card_{safe}.token")


@dataclass(slots=True)
class ConsumerProcess:
    """The HIL supervisor a modem rig runs while its session is held."""

    rig: RigConfig
    offer: CardOffer
    popen_factory: Any = subprocess.Popen
    _child: Any = None
    _token_path: str = ""
    _command: tuple[str, ...] = ()

    def build_command(self) -> list[str]:
        """Assemble the supervisor invocation for this rig and offer."""
        consumer = self.rig.consumer
        executable = shutil.which(consumer.supervisor) or consumer.supervisor
        command = [
            executable,
            "--remote-card-url",
            self.offer.url,
            "--usb-vidpid",
            self.rig.modem.simtrace_vidpid,
            "--simtrace-reset",
            consumer.simtrace_reset,
            "--host",
            consumer.bridge_host,
            "--port",
            str(consumer.bridge_port),
            "--advertise-host",
            consumer.bridge_host,
            "--apdu-timeout-ms",
            str(consumer.apdu_timeout_ms),
        ]
        if len(self._token_path) > 0:
            command.extend(["--remote-card-token-file", self._token_path])
        command.extend(consumer.extra_args)
        return command

    def start(self) -> None:
        """Stage the token, then start the child in its own process group."""
        if self.rig.consumer.enabled is False:
            raise CardOfferError(
                f"rig {self.rig.id} is not configured to consume an offered card"
            )
        if self.is_running() is True:
            return
        self._stage_token()
        command = self.build_command()
        self._command = tuple(command)
        try:
            self._child = self.popen_factory(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as start_error:
            self._clear_token()
            raise RuntimeError(
                f"Cannot start the card consumer for rig {self.rig.id}: "
                f"{start_error}"
            ) from start_error
        _LOGGER.info(
            "remote_lab consumer started rig=%s pid=%s card=%s",
            self.rig.id,
            getattr(self._child, "pid", ""),
            self.offer.url,
        )

    def stop(self) -> None:
        """Stop the child and remove the staged token."""
        child = self._child
        self._child = None
        if child is not None and child.poll() is None:
            self._terminate(child)
        self._clear_token()

    def is_running(self) -> bool:
        child = self._child
        return child is not None and child.poll() is None

    def state(self) -> dict[str, Any]:
        """Operator-visible state. Never carries the offered token."""
        return {
            "running": self.is_running(),
            "pid": int(getattr(self._child, "pid", 0) or 0),
            "card": self.offer.redacted(),
            "supervisor": self.rig.consumer.supervisor,
        }

    def _terminate(self, child: Any) -> None:
        try:
            os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        except (OSError, AttributeError):
            try:
                child.terminate()
            except OSError:
                return
        try:
            child.wait(timeout=CONSUMER_TERMINATION_TIMEOUT_SECONDS)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(os.getpgid(child.pid), _SIGKILL)
        except (OSError, AttributeError):
            try:
                child.kill()
            except OSError:
                return
        try:
            child.wait(timeout=CONSUMER_TERMINATION_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            _LOGGER.warning(
                "remote_lab consumer for rig %s did not exit", self.rig.id
            )

    def _stage_token(self) -> None:
        if len(self.offer.token) == 0:
            return
        path = consumer_token_path(self.rig.id)
        try:
            ensure_runtime_dir(os.path.dirname(path))
            write_token_file(Path(path), self.offer.token)
        except OSError as write_error:
            raise RuntimeError(
                f"Cannot stage the offered card token for rig {self.rig.id}: "
                f"{write_error}"
            ) from write_error
        self._token_path = path

    def _clear_token(self) -> None:
        path = self._token_path
        self._token_path = ""
        if len(path) == 0:
            return
        try:
            os.remove(path)
        except FileNotFoundError:
            return
        except OSError as remove_error:
            _LOGGER.warning(
                "remote_lab could not remove %s: %s", path, remove_error
            )


class ConsumerManager:
    """Consumers in flight, at most one per rig.

    The map is keyed by rig id and a rig can hold one session at a time,
    so it is bounded by the configured rig count and needs no cap.
    """

    def __init__(self, *, popen_factory: Any = subprocess.Popen) -> None:
        self._popen_factory = popen_factory
        self._lock = threading.Lock()
        self._processes: dict[str, ConsumerProcess] = {}

    def start(self, rig: RigConfig, offer: CardOffer) -> ConsumerProcess:
        with self._lock:
            existing = self._processes.pop(rig.id, None)
        if existing is not None:
            existing.stop()
        process = ConsumerProcess(
            rig=rig, offer=offer, popen_factory=self._popen_factory
        )
        process.start()
        with self._lock:
            self._processes[rig.id] = process
        return process

    def stop(self, rig_id: str) -> None:
        with self._lock:
            process = self._processes.pop(str(rig_id or ""), None)
        if process is not None:
            process.stop()

    def stop_all(self) -> None:
        with self._lock:
            processes = list(self._processes.values())
            self._processes.clear()
        for process in processes:
            process.stop()

    def state_for(self, rig_id: str) -> dict[str, Any]:
        with self._lock:
            process = self._processes.get(str(rig_id or ""))
        if process is None:
            return {"running": False}
        return process.state()
