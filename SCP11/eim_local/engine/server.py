# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The Local eIM as a background service: ESipa, the local SM-DP+ and the local SM-DS in their own process.

``start_background`` launches ``python -m SCP11.eim_local.engine.server run``
detached from the caller, so the service keeps answering after the shell or
the GUI that started it closes. The running process writes ``server.json`` in
the engine store (pid, URL, eIM FQDN, SM-DP+ and SM-DS address) and removes
it when it stops. ``local_route`` reads that file: an IPA in any other
YggdraSIM process whose eIM FQDN, SM-DP+ address or SM-DS address names this
service is sent to its loopback URL instead of resolving the name, which is
how the eSIM Management console's DOWNLOAD and any other IPA reach it like any
other eIM.

Beside that plain loopback listener runs the card-facing TLS listener
(``tls_port``, the next port by default): a card's IPAe that resolves the eIM
FQDN through the terminal driving it is carried there, and authenticates the
chain the TLS setup in use serves (``tls_setup``). A third listener
(``smdp_tls_port``, the port after that) is the local SM-DP+ for a card that
downloads directly: it serves the SM-DP+'s TLS certificate (``smdp_tls``) and
answers ES9+ in the ASN.1 binding. A fourth (``smds_tls_port``, four past the
plain one, because the port in between is the default of the IPAd's
EIM-LISTEN) is the local SM-DS for a card whose IPAe retrieves its Event
Records itself: it serves CERT.DS.TLS and answers ES11.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from SCP11.eim_local.engine.identity import local_eim_name
from SCP11.eim_local.engine.esipa import LocalEimCardTlsServer, LocalEimHttpServer, card_tls_context, card_tls_contexts
from SCP11.eim_local.engine.notifications import Forwarder, receiver_sender
from SCP11.eim_local.engine.service import SETTING_TLS_KEYLOG, LocalEim
from SCP11.eim_local.engine.smdp import LocalSmdp
from SCP11.eim_local.engine.smds import LocalSmds
from SCP11.eim_local.engine.smdp_tls import SmdpTlsError, smds_serving_material
from SCP11.eim_local.engine.smdp_tls import serving_material as smdp_serving_material
from SCP11.eim_local.engine.store import store_directory
from SCP11.eim_local.engine.tls_setup import (
    certificate_sha256,
    effective_fqdn,
    list_setups,
    listener_groups,
    served_materials,
)

STATUS_FILE = "server.json"
LOG_FILE = "server.log"
KEYLOG_FILE = "tls-keylog.txt"
LOG_MAX_OCTETS = 1 << 20
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8743
START_WAIT_S = 15.0


class ServiceError(RuntimeError):
    """The background service did not start, stop or answer as asked."""


class _Log:
    """Append-only service log, rolled to ``server.log.1`` past 1 MiB."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def __call__(self, line: str) -> None:
        stamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
        with self._lock:
            try:
                if self.path.exists() and self.path.stat().st_size > LOG_MAX_OCTETS:
                    self.path.replace(self.path.with_name(LOG_FILE + ".1"))
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(f"{stamp} {line}\n")
            except OSError:
                pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    try:
        # A process that exited but was not reaped still answers kill(0).
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace").rsplit(")", 1)[-1].split()
    except OSError:
        return True
    return not (fields and fields[0] in ("Z", "X"))


def read_status(directory: Path | None = None) -> dict[str, Any] | None:
    """The running service's ``server.json``, or None when no live process owns it."""
    path = Path(directory or store_directory()) / STATUS_FILE
    try:
        status = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    if not isinstance(status, dict) or not _pid_alive(int(status.get("pid", 0) or 0)):
        return None
    return status


def _host_of(name: str) -> str:
    text = str(name or "").strip().lower()
    if "://" in text:
        text = urlparse(text).hostname or ""
    return text.split("/", 1)[0].split(":", 1)[0].rstrip(".")


def local_route(name: str, directory: Path | None = None) -> str:
    """Return the running service's URL when *name* is its eIM FQDN, SM-DP+ address or SM-DS address, else ''."""
    host = _host_of(name)
    if len(host) == 0:
        return ""
    status = read_status(directory)
    if status is None:
        return ""
    listed = status.get("eim_fqdns")
    names = {_host_of(str(item)) for item in (listed if isinstance(listed, list) else [])}
    names.add(_host_of(str(status.get("eim_fqdn", ""))))
    # The status file is not trusted for the eIM names: a service started before the name rule lists others.
    names = {item for item in names if local_eim_name(item)}
    names.add(_host_of(str(status.get("smdp_address", ""))))
    names.add(_host_of(str(status.get("smds_address", ""))))
    names.discard("")
    # Every Local eIM name is the service's, whether a setup carries it or not.
    if host in names or local_eim_name(host):
        return str(status.get("url", "")).rstrip("/")
    return ""


def ping(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/ping", timeout=timeout) as response:  # noqa: S310 - loopback URL of our own service
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def card_port(port: int, value: str | int | None, *, offset: int = 1, name: str = "tls_port") -> int | None:
    """A card-facing TLS port for *value*: ``auto`` is *offset* past *port* (any port for 0), ``off`` none."""
    text = str(value if value is not None else "auto").strip().lower()
    if text in ("off", "none", "no"):
        return None
    if text in ("auto", ""):
        return int(port) + int(offset) if int(port) > 0 else 0
    try:
        number = int(text)
    except ValueError as error:
        raise ServiceError(f"{name} is a port number, auto or off; got {value!r}.") from error
    if not 0 <= number <= 65535:
        raise ServiceError(f"{name} {number} is not a port.")
    return number


def smdp_card_port(port: int, value: str | int | None) -> int | None:
    """The SM-DP+ card-facing TLS port: ``auto`` is two past *port*, after the eIM's card-facing one."""
    return card_port(port, value, offset=2, name="smdp_tls_port")


def smds_card_port(port: int, value: str | int | None) -> int | None:
    """The SM-DS card-facing TLS port: ``auto`` is four past *port*. Three past it is the default port of the
    eSIM Management console's EIM-LISTEN, which runs beside this service on the same host."""
    return card_port(port, value, offset=4, name="smds_tls_port")


def _eim_fqdns(directory: Path, identity: Any) -> list[str]:
    """The eIM FQDNs the service answers for: the setup in use's, the identity's, then every other setup's, without repeats.

    A card keeps the name its AddInitialEim carried, so every setup's name is
    answered while the service runs, whichever card is in the reader. Only
    names of ``LOCAL_EIM_NAME_PATTERN`` are listed: a setup or identity under
    any other name is served to nobody, because nothing routes that name here.
    """
    names = [effective_fqdn(directory, identity), identity.eim_fqdn if identity else ""]
    names.extend(setup.effective_fqdn for setup in list_setups(directory))
    return [name for name in dict.fromkeys(names) if local_eim_name(name)]


def _card_listeners(
    engine: LocalEim, smdp: LocalSmdp, host: str, port: int | None, relay: Any, log: _Log, keylog_path: str = "",
    smds: LocalSmds | None = None,
) -> tuple[list[LocalEimCardTlsServer], dict[str, Any]]:
    """The card-facing listeners: one for the chains picked by server name on *port*, one more per mutual-TLS chain.

    The status names every setup and host name served and the port each
    name goes to (``tls_ports_by_name``), which the IPAe route reads.
    *keylog_path* goes to every context served (the tls_keylog setting).
    """
    if port is None:
        return [], {"tls_url": "", "tls_note": "card-facing TLS listener off (tls_port=off)"}
    materials = served_materials(engine.directory, engine.identity_or_none())
    if len(materials) == 0:
        note = "no card-facing TLS listener: the identity has no TLS certificate and no TLS setup is in use"
        log(note)
        return [], {"tls_url": "", "tls_note": note}
    servers: list[LocalEimCardTlsServer] = []
    listeners: list[dict[str, Any]] = []
    ports_by_name: dict[str, int] = {}
    skipped: list[str] = []
    for index, group in enumerate(listener_groups(materials)):
        # A chain that does not load is left out with a note; the default's failure, or a port in use, leaves the
        # IPAd listener serving alone and the note says why.
        loadable = []
        for item in group:
            try:
                card_tls_context(item.chain_path, item.key_path, versions=item.versions, ciphers=item.ciphers,
                                 client_auth=item.client_auth, client_ca_path=item.client_ca_path)
            except ValueError as error:
                note = f"no card-facing TLS listener ({item.label}): {error}"
                log(note)
                if index == 0 and item is materials[0]:
                    return [], {"tls_url": "", "tls_note": note}
                skipped.append(item.label)
                continue
            loadable.append(item)
        if len(loadable) == 0:
            continue
        try:
            context = card_tls_contexts(loadable, keylog_path=keylog_path)
            server = LocalEimCardTlsServer(engine, (host, port if index == 0 else 0), context, smdp=smdp, smds=smds,
                                           log=log, relay=relay, tls_label=loadable[0].label,
                                           leaves={item.label: (item.leaf, item.leaf_sha256) for item in loadable})
        except (ValueError, OSError) as error:
            note = f"no card-facing TLS listener ({loadable[0].label}): {error}"
            log(note)
            if index == 0:
                return [], {"tls_url": "", "tls_note": note}
            continue
        group = loadable
        servers.append(server)
        bound = int(server.server_address[1])
        names = sorted({name for item in group for name in (*item.names, *item.patterns)})
        for name in names:
            ports_by_name.setdefault(name, bound)
        listeners.append({"url": server.url, "port": bound, "setups": [item.label for item in group],
                          "names": names, "client_auth": group[0].client_auth})
    first = materials[0]
    return servers, {"tls_url": servers[0].url, "tls_host": host, "tls_port": int(servers[0].server_address[1]),
                     "tls_setup": first.label, "tls_versions": first.versions,
                     "tls_client_auth": first.client_auth, "tls_sni": "required" if first.sni_names else "any",
                     "tls_setups_served": [item for listener in listeners for item in listener["setups"]],
                     "tls_setups_skipped": skipped,
                     "tls_names_served": sorted(ports_by_name), "tls_ports_by_name": ports_by_name,
                     "tls_listeners": listeners}


def _keylog_path(engine: LocalEim, directory: Path, log: _Log) -> str:
    """The NSS key log file the card-facing contexts append to while the tls_keylog setting is on, else ''.

    The file is the operator's own (mode 0600): Wireshark reads it to decrypt
    a capture of the sessions the listeners served, which is how the TLS
    inside a SIMtrace or modem capture is read.
    """
    if not bool(engine.setting(SETTING_TLS_KEYLOG)):
        return ""
    path = directory / KEYLOG_FILE
    try:
        path.touch(mode=0o600, exist_ok=True)
        os.chmod(path, 0o600)
    except OSError as error:
        log(f"TLS key log not written: {error}")
        return ""
    log(f"TLS key log: {path} (NSS key log format)")
    return str(path)


def _smdp_card_listener(
    engine: LocalEim, smdp: LocalSmdp, host: str, port: int | None, relay: Any, log: _Log, keylog_path: str = "",
    smds: LocalSmds | None = None,
) -> tuple[LocalEimCardTlsServer | None, dict[str, Any]]:
    """The listener a card's IPAe reaches the local SM-DP+ on, serving CERT.DP.TLS; None with the reason."""
    if port is None:
        return None, {"smdp_tls_url": "", "smdp_tls_note": "SM-DP+ card-facing TLS listener off (smdp_tls_port=off)"}
    # No certificate, a chain that does not load or a port in use leaves the other listeners serving.
    try:
        material = smdp_serving_material(engine.directory, smdp)
        context = card_tls_context(material.chain_path, material.key_path, versions=material.versions,
                                   ciphers=material.ciphers, keylog_path=keylog_path)
        server = LocalEimCardTlsServer(engine, (host, port), context, smdp=smdp, smds=smds, log=log, relay=relay,
                                       tls_label=material.label,
                                       leaves={material.label: ("CERT.DP.TLS",
                                                                certificate_sha256(Path(material.chain_path)))})
    except (SmdpTlsError, ValueError, OSError, RuntimeError, LookupError) as error:
        note = f"no SM-DP+ card-facing TLS listener: {error}"
        log(note)
        return None, {"smdp_tls_url": "", "smdp_tls_note": note}
    return server, {"smdp_tls_url": server.url, "smdp_tls_host": host, "smdp_tls_port": server.server_address[1],
                    "smdp_tls_material": material.label}


def _smds_card_listener(
    engine: LocalEim, smdp: LocalSmdp, smds: LocalSmds, host: str, port: int | None, relay: Any, log: _Log,
    keylog_path: str = "",
) -> tuple[LocalEimCardTlsServer | None, dict[str, Any]]:
    """The listener a card's IPAe reaches the local SM-DS on, serving CERT.DS.TLS; None with the reason.

    An IPAe that retrieves its Event Records itself opens its own TLS session
    to the SM-DS (SGP.32 v1.3 §3.9.2.1, §5.10) and authenticates it by a chain
    to an eSIM CA the eUICC holds.
    """
    if port is None:
        return None, {"smds_tls_url": "", "smds_tls_note": "SM-DS card-facing TLS listener off (smds_tls_port=off)"}
    if smds.taken_by_the_smdp():
        note = (f"no SM-DS card-facing TLS listener: {smds.address()} is also the address of the SM-DP+, which "
                "keeps the name")
        log(note)
        return None, {"smds_tls_url": "", "smds_tls_note": note}
    # No certificate, a chain that does not load or a port in use leaves the other listeners serving.
    try:
        material = smds_serving_material(engine.directory, smds)
        context = card_tls_context(material.chain_path, material.key_path, versions=material.versions,
                                   ciphers=material.ciphers, keylog_path=keylog_path)
        server = LocalEimCardTlsServer(engine, (host, port), context, smdp=smdp, smds=smds, log=log, relay=relay,
                                       tls_label=material.label,
                                       leaves={material.label: ("CERT.DS.TLS",
                                                                certificate_sha256(Path(material.chain_path)))})
    except (SmdpTlsError, ValueError, OSError, RuntimeError, LookupError) as error:
        note = f"no SM-DS card-facing TLS listener: {error}"
        log(note)
        return None, {"smds_tls_url": "", "smds_tls_note": note}
    return server, {"smds_tls_url": server.url, "smds_tls_host": host, "smds_tls_port": server.server_address[1],
                    "smds_tls_material": material.label}


def run(
    directory: Path,
    host: str,
    port: int,
    tls: bool,
    tls_port: int | None = None,
    smdp_tls_port: int | None = None,
    smds_tls_port: int | None = None,
) -> int:
    """Serve until SIGTERM / SIGINT; the body of the background process."""
    engine = LocalEim(directory)
    log = _Log(directory / LOG_FILE)
    smdp = LocalSmdp(directory)
    smds = LocalSmds(directory, store=engine.store)
    identity = engine.identity_or_none()
    tls_material: tuple[str, str] | None = None
    if tls:
        if identity is None or not identity.tls_certificate_path or not identity.tls_key_path:
            raise ServiceError("TLS needs an identity with a TLS certificate and key (IDENTITY NEW).")
        tls_material = (identity.tls_certificate_path, identity.tls_key_path)
    server = LocalEimHttpServer(engine, (host, port), smdp=smdp, smds=smds, tls=tls_material, log=log)
    keylog_path = _keylog_path(engine, directory, log)
    card_servers, card_status = _card_listeners(engine, smdp, host, tls_port, server.relay, log, keylog_path, smds)
    smdp_server, smdp_status = _smdp_card_listener(engine, smdp, host, smdp_tls_port, server.relay, log,
                                                   keylog_path, smds)
    smds_server, smds_status = _smds_card_listener(engine, smdp, smds, host, smds_tls_port, server.relay, log,
                                                   keylog_path)
    status = {
        "pid": os.getpid(),
        "url": server.url,
        "host": host,
        "port": server.server_address[1],
        "tls": tls,
        "tls_keylog": keylog_path,
        "store": str(directory),
        # What was asked, so a restart asks again even when this start got no listener.
        "tls_requested": "off" if tls_port is None else int(tls_port),
        **card_status,
        "smdp_tls_requested": "off" if smdp_tls_port is None else int(smdp_tls_port),
        **smdp_status,
        "eim_id": identity.eim_id if identity else "",
        # The FQDN the TLS setup in use stands for comes first; the identity's own is answered too.
        "eim_fqdn": effective_fqdn(directory, identity),
        "eim_fqdns": _eim_fqdns(directory, identity),
        "smdp_address": smdp.address(),
        "smdp_fqdn": smdp.host(),
        # The SM-DS answers on the same listeners, under the name it had when the service started.
        "smds_address": smds.address(),
        "smds_tls_requested": "off" if smds_tls_port is None else int(smds_tls_port),
        **smds_status,
        "started_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
    }
    status_path = directory / STATUS_FILE
    status_path.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    log(f"started: {server.url} eIM {status['eim_fqdn'] or '-'} SM-DP+ {status['smdp_address'] or '-'} "
        f"SM-DS {status['smds_address'] or '-'}")
    for listener in status.get("tls_listeners", []):
        log(f"card-facing TLS: {listener['url']} serving {', '.join(listener['setups'])} for "
            f"{', '.join(listener['names']) or '-'} (client auth {listener['client_auth']})")
    if smdp_server is not None:
        log(f"SM-DP+ card-facing TLS: {smdp_server.url} for {status['smdp_fqdn'] or '-'}, "
            f"certificate {status['smdp_tls_material']}")
    if smds_server is not None:
        log(f"SM-DS card-facing TLS: {smds_server.url} for {status['smds_address'] or '-'}, "
            f"certificate {status['smds_tls_material']}")
    stop = threading.Event()

    def _on_signal(_number: int, _frame: Any) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    # One forwarder for every listener: Notifications an IPA hands over go on to their receivers
    # after the answer, and the ones a receiver did not take are tried again while the service runs.
    forwarder = Forwarder(engine, receiver_sender(engine, smdp), log=log)
    rsp_servers = [listener for listener in (smdp_server, smds_server) if listener is not None]
    for listener in (server, *card_servers, *rsp_servers):
        listener.forwarder = forwarder
    forwarder.start()
    forwarder.kick()
    server.start_in_thread()
    for card_server in card_servers:
        card_server.start_in_thread()
    for rsp_server in rsp_servers:
        rsp_server.start_in_thread()
    try:
        while not stop.wait(1.0):
            pass
    finally:
        forwarder.stop()
        for rsp_server in reversed(rsp_servers):
            rsp_server.stop()
        for card_server in card_servers:
            card_server.stop()
        server.stop()
        try:
            current = json.loads(status_path.read_text(encoding="utf-8"))
            if int(current.get("pid", 0)) == os.getpid():
                status_path.unlink()
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass
        log("stopped")
    return 0


def start_background(
    directory: Path | None = None,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    tls: bool = False,
    tls_port: str | int | None = "auto",
    smdp_tls_port: str | int | None = "auto",
    smds_tls_port: str | int | None = "auto",
) -> dict[str, Any]:
    """Launch the service detached and wait until it answers /ping; return its status."""
    folder = Path(directory or store_directory())
    running = read_status(folder)
    if running is not None:
        return running
    folder.mkdir(parents=True, exist_ok=True)
    repo_root = Path(__file__).resolve().parents[3]
    environment = dict(os.environ)
    environment["YGGDRASIM_LOCAL_EIM_STORE"] = str(folder)
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(repo_root), environment.get("PYTHONPATH", "")) if part
    )
    arguments = ["--host", host, "--port", str(int(port)),
                 "--tls-port", str(tls_port if tls_port is not None else "off"),
                 "--smdp-tls-port", str(smdp_tls_port if smdp_tls_port is not None else "off"),
                 "--smds-tls-port", str(smds_tls_port if smds_tls_port is not None else "off")]
    if tls:
        arguments.append("--tls")
    if os.name == "nt":
        _spawn(["run", *arguments], folder, repo_root, environment, detach=True)
    else:
        # Through an intermediate process that exits at once: the service is
        # reparented and never lingers unreaped under the shell that started it.
        launcher = subprocess.run(  # noqa: S603 - our own interpreter and module
            [sys.executable, "-m", "SCP11.eim_local.engine.server", "spawn", *arguments],
            cwd=str(repo_root), env=environment, capture_output=True, text=True, timeout=START_WAIT_S,
        )
        if launcher.returncode != 0:
            raise ServiceError(f"The Local eIM service launcher failed: {launcher.stderr.strip()[-400:]}")
    deadline = time.monotonic() + START_WAIT_S
    while time.monotonic() < deadline:
        status = read_status(folder)
        if status is not None and ping(str(status.get("url", "")), timeout=1.0):
            return status
        time.sleep(0.2)
    raise ServiceError(f"The Local eIM service did not answer within {START_WAIT_S:.0f} s; see {folder / LOG_FILE}.")


def _spawn(arguments: list[str], folder: Path, repo_root: Path, environment: dict[str, str], *, detach: bool) -> int:
    log_handle = (folder / LOG_FILE).open("a", encoding="utf-8")
    options: dict[str, Any] = {}
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    elif detach:
        options["start_new_session"] = True
    try:
        process = subprocess.Popen(  # noqa: S603 - our own interpreter and module
            [sys.executable, "-m", "SCP11.eim_local.engine.server", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            cwd=str(repo_root),
            env=environment,
            **options,
        )
    finally:
        log_handle.close()
    return int(process.pid)


def restart_background(directory: Path | None = None) -> dict[str, Any] | None:
    """Restart a running service on the same addresses (a new TLS setup is served); None when none ran."""
    folder = Path(directory or store_directory())
    status = read_status(folder)
    if status is None:
        return None
    if status.get("tls_url"):
        tls_port: str | int = int(status["tls_port"])
    else:
        tls_port = status.get("tls_requested", "off")
    if status.get("smdp_tls_url"):
        smdp_tls_port: str | int = int(status["smdp_tls_port"])
    else:
        # A status file written before the SM-DP+ listener existed asks for the default.
        smdp_tls_port = status.get("smdp_tls_requested", "auto")
    if status.get("smds_tls_url"):
        smds_tls_port: str | int = int(status["smds_tls_port"])
    else:
        # The same for the SM-DS listener: a service older than it is restarted with the default.
        smds_tls_port = status.get("smds_tls_requested", "auto")
    stop_background(folder)
    return start_background(folder, host=str(status.get("host", DEFAULT_HOST)), port=int(status.get("port", DEFAULT_PORT)),
                            tls=bool(status.get("tls", False)), tls_port=tls_port, smdp_tls_port=smdp_tls_port,
                            smds_tls_port=smds_tls_port)


def stop_background(directory: Path | None = None, *, wait_s: float = 5.0) -> bool:
    """Stop the running service; False when none was running."""
    folder = Path(directory or store_directory())
    status = read_status(folder)
    if status is None:
        return False
    pid = int(status.get("pid", 0))
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.1)
    raise ServiceError(f"The Local eIM service (pid {pid}) did not stop within {wait_s:.0f} s.")


def describe(directory: Path | None = None) -> dict[str, Any]:
    """Status for the shell, the GUI and MCP: running or not, and where."""
    folder = Path(directory or store_directory())
    status = read_status(folder)
    if status is None:
        return {"running": False, "store": str(folder), "log": str(folder / LOG_FILE)}
    return {**status, "running": True, "answers": ping(str(status.get("url", ""))),
            "store": str(folder), "log": str(folder / LOG_FILE)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m SCP11.eim_local.engine.server",
                                     description="Local eIM service: ESipa, the local SM-DP+ and the local SM-DS.")
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("run", "start", "spawn"):
        command = sub.add_parser(name)
        command.add_argument("--host", default=DEFAULT_HOST)
        command.add_argument("--port", type=int, default=DEFAULT_PORT)
        command.add_argument("--tls", action="store_true")
        command.add_argument("--tls-port", default="auto")
        command.add_argument("--smdp-tls-port", default="auto")
        command.add_argument("--smds-tls-port", default="auto")
    sub.add_parser("stop")
    sub.add_parser("status")
    arguments = parser.parse_args(argv)
    folder = store_directory()
    if arguments.action == "run":
        return run(folder, arguments.host, arguments.port, arguments.tls, card_port(arguments.port, arguments.tls_port),
                   smdp_card_port(arguments.port, arguments.smdp_tls_port),
                   smds_card_port(arguments.port, arguments.smds_tls_port))
    if arguments.action == "spawn":
        command = ["run", "--host", arguments.host, "--port", str(arguments.port), "--tls-port", arguments.tls_port,
                   "--smdp-tls-port", arguments.smdp_tls_port, "--smds-tls-port", arguments.smds_tls_port]
        if arguments.tls:
            command.append("--tls")
        print(_spawn(command, folder, Path(__file__).resolve().parents[3], dict(os.environ), detach=True))
        return 0
    if arguments.action == "start":
        print(json.dumps(start_background(folder, host=arguments.host, port=arguments.port, tls=arguments.tls,
                                          tls_port=arguments.tls_port, smdp_tls_port=arguments.smdp_tls_port,
                                          smds_tls_port=arguments.smds_tls_port),
                         indent=2))
        return 0
    if arguments.action == "stop":
        print("stopped" if stop_background(folder) else "not running")
        return 0
    print(json.dumps(describe(folder), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
