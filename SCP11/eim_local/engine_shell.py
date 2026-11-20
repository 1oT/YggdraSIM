# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Operation-queue verbs of the Local eIM shell.

QUEUE takes operations (ENABLE, DOWNLOAD, ADD-EIM, ...) for one eUICC,
OPS / OP / EDIT / MOVE / CANCEL / COPY manage the queue, EUICC / IDENTITY /
ASSOCIATE set up the eIM and its cards, and SERVE / DELIVER hand the queue to
an IPA: the background ESipa service (the eSIM Management console's DOWNLOAD
and any other IPA that polls the eIM FQDN reach it), or the shell itself
acting as IPAd on the card in the reader.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Callable

from SCP11.eim_local.engine import cert_spec, codec, tls_results, traffic
from SCP11.eim_local.engine.catalogue import FAULTS, OPERATION_TYPES, OperationError, operation_type
from SCP11.eim_local.engine.delivery import DeliveryError, deliver, read_card, read_signing_ci_pkids
from SCP11.eim_local.engine.identity import IdentityError, local_eim_name
from SCP11.eim_local.engine.inject import (
    DEFAULT_TIMEOUT_S,
    InjectError,
    TargetUnreachable,
    TrafficLog,
    inject,
    parse_target,
    transport_for,
)
from SCP11.eim_local.engine import tls_setup
from SCP11.eim_local.engine.server import (
    DEFAULT_PORT,
    ServiceError,
    describe,
    restart_background,
    start_background,
    stop_background,
)
from SCP11.eim_local.engine import notifications as outbox
from SCP11.eim_local.engine.service import (
    SETTING_DEFAULTS,
    SETTING_SMDS_ADDRESS,
    LocalEim,
    LocalEimError,
    OperationRequest,
    check_association_name,
)
from SCP11.eim_local.engine.smdp import LocalSmdp, SmdpError
from SCP11.eim_local.engine.smds import EVENT_TYPE_PROFILE_DOWNLOAD, EVENT_TYPE_RPM, EVENT_TYPES, LocalSmds, SmdsError
from SCP11.eim_local.engine.store import StoreError, store_directory
from SCP11.shared.ipad_declaration import declare_ipad, forget_ipad_declaration
from yggdrasim_common.reader_locks import ReaderBusyError

# A certificate text is a few dozen lines; a larger file named as one is something else.
_CERTIFICATE_TEXT_MAX = 65536

QUEUE_VERBS: dict[str, str] = {
    "DOWNLOAD": "PROFILE_DOWNLOAD_TRIGGER",
    "ENABLE": "ENABLE_PROFILE",
    "DISABLE": "DISABLE_PROFILE",
    "DELETE": "DELETE_PROFILE",
    "LIST-PROFILES": "PROFILE_INFO_LIST",
    "GET-RAT": "GET_RAT",
    "IMMEDIATE-ENABLE": "CONFIGURE_IMMEDIATE_ENABLE",
    "FALLBACK": "SET_FALLBACK_ATTRIBUTE",
    "UNSET-FALLBACK": "UNSET_FALLBACK_ATTRIBUTE",
    "DEFAULT-SMDP": "SET_DEFAULT_DP_ADDRESS",
    "ADD-EIM": "ADD_EIM",
    "UPDATE-EIM": "UPDATE_EIM",
    "DELETE-EIM": "DELETE_EIM",
    "LIST-EIM": "LIST_EIM",
    "IPA-DATA": "IPA_EUICC_DATA",
    "RAW-PSMO": "PSMO_RAW",
    "RAW-ECO": "ECO_RAW",
    "ROLLBACK": "PROFILE_ROLLBACK",
    "EXECUTE-FALLBACK": "EXECUTE_FALLBACK",
    "RETURN-FALLBACK": "RETURN_FROM_FALLBACK",
}
# The parameter a bare positional value fills, per operation type.
POSITIONAL: dict[str, str] = {
    "PROFILE_DOWNLOAD_TRIGGER": "activation_code",
    "ENABLE_PROFILE": "iccid",
    "DISABLE_PROFILE": "iccid",
    "DELETE_PROFILE": "iccid",
    "SET_FALLBACK_ATTRIBUTE": "iccid",
    "PROFILE_INFO_LIST": "tags",
    "IPA_EUICC_DATA": "tags",
    "CONFIGURE_IMMEDIATE_ENABLE": "enabled",
    "SET_DEFAULT_DP_ADDRESS": "address",
    "ADD_EIM": "eim_id",
    "UPDATE_EIM": "eim_id",
    "DELETE_EIM": "eim_id",
    "PSMO_RAW": "items",
    "ECO_RAW": "items",
}
REFRESH_TYPES = ("PROFILE_INFO_LIST", "LIST_EIM", "IPA_EUICC_DATA")

DOCS: dict[str, dict[str, Any]] = {
    "QUEUE": {
        "usage": "QUEUE <operation> [eid] [value] [key=value ...] [--plan] [--first] [--at <UTC>] "
                 "[--retries <n>] [--fault <kind>] [--eid-file <file>]",
        "summary": "Queue an operation for an eUICC; it is signed when an IPA takes it. "
                   "Operations: " + ", ".join(sorted([*QUEUE_VERBS, "REFRESH"])) + ".",
        "examples": [
            "QUEUE ENABLE 89049032123451234512345678901235 8988211111111111112 rollback=on",
            "QUEUE DOWNLOAD 1$smdpp.example.test$MID-1",
            "QUEUE LIST-PROFILES --plan",
            "QUEUE REFRESH",
            "QUEUE GET-RAT --fault stale-counter",
        ],
    },
    "OPS": {
        "usage": "OPS [pending|completed|all] [eid=<eid>] [type=<TYPE>] [limit=<n>] [--json]",
        "summary": "List operations, newest first.",
        "examples": ["OPS", "OPS completed limit=20", "OPS all type=ENABLE_PROFILE"],
    },
    "OP": {"usage": "OP <id> [--decode] [--json]",
           "summary": "One operation: parameters, timeline, served package, result; --decode adds the Decoder's "
                      "reading of the package and the result (every data object by name and value).",
           "examples": ["OP 12", "OP 12 --decode"]},
    "EDIT": {
        "usage": "EDIT <id> key=value ... (type= raw= at= retries= fault=; key= with nothing removes it)",
        "summary": "Change a CREATED operation; a SENT one takes only retries=.",
        "examples": ["EDIT 12 iccid=8988211111111111129", "EDIT 12 at=2026-11-06T08:00Z", "EDIT 12 raw=A600BF2D00"],
    },
    "MOVE": {"usage": "MOVE <id> first|last|up|down|before <id>|after <id>",
             "summary": "Reorder a CREATED operation in its eUICC's queue.", "examples": ["MOVE 14 first"]},
    "CANCEL": {"usage": "CANCEL <id> | CANCEL eid=<eid>",
               "summary": "Cancel a queued operation (a SENT one is given up; the card may have run it).",
               "examples": ["CANCEL 12", "CANCEL eid=89049032123451234512345678901235"]},
    "COPY": {"usage": "COPY <id> [key=value ...]", "summary": "Queue a copy of any operation, optionally changed.",
             "examples": ["COPY 12", "COPY 12 iccid=8988211111111111129"]},
    "EXPORT": {"usage": "EXPORT <id>", "summary": "Sign a CREATED operation for another IPA: package hex and STORE DATA APDUs.",
               "examples": ["EXPORT 12"]},
    "RESULT": {"usage": "RESULT <id> <hex>", "summary": "Close an operation with an EimPackageResult obtained elsewhere.",
               "examples": ["RESULT 12 BF51..."]},
    "EUICC": {
        "usage": "EUICC [list] | EUICC <eid> | EUICC ADD <eid> [label] | EUICC READ | EUICC SET <eid> key=value ... "
                 "| EUICC REMOVE <eid>",
        "summary": "eUICC records: what the eIM knows about each card.",
        "examples": ["EUICC", "EUICC READ", "EUICC SET 89049032123451234512345678901235 counter_value=40"],
    },
    "IDENTITY": {
        "usage": "IDENTITY [show] | IDENTITY NEW [eimId] [fqdn] | IDENTITY IMPORT eim_id=... fqdn=... key=... cert=... "
                 "[tls_key=... tls_cert=...]",
        "summary": "The Local eIM's own eimId, signing key and certificates.",
        "examples": ["IDENTITY", "IDENTITY NEW 1.3.6.1.4.1.32473.999.10.124 eim.yggdrasim.local"],
    },
    "ASSOCIATE": {"usage": "ASSOCIATE [setup=<name>|identity] [fqdn=<eimN.yggdrasim.local>] [--yes] [--public-key] [--no-reset] | ASSOCIATE CHOICES | "
                           "ASSOCIATE HANDOVER eim_id=<id> sign=<stored cert> [fqdn=<host>] [eim_id_type=oid|fqdn|proprietary] "
                           "[tls=<stored cert>|none] [--public-key] [--tls-key] [counter=<n>] [ci_pkid=<hex>|card] "
                           "[indirect=on|off] [protocols=<a,b>] [--yes] [--no-reset]",
                  "summary": "Put this eIM on the card in the reader: eUICCMemoryReset of the eIM configuration, then "
                             "AddInitialEim with the identity's key and the eIM FQDN and TLS trust of the TLS setup in use "
                             "(setup= puts one in use first; fqdn= gives the card another Local eIM name the setup's wildcard leaf "
                             "covers). CHOICES lists what can be picked. HANDOVER puts another eIM's "
                             "stored certificates on the card instead, with the eimId, FQDN and counter given.",
                  "examples": ["ASSOCIATE", "ASSOCIATE setup=other-eim --yes", "ASSOCIATE CHOICES",
                               "ASSOCIATE HANDOVER eim_id=2.999.1 fqdn=eim.example.test sign=OTHER-EIM tls=OTHER-ROOT "
                               "ci_pkid=card indirect=on"]},
    "SERVE": {"usage": "SERVE [status|start|stop|restart] [port=<n>] [host=<addr>] [tls_port=<n>|auto|off] "
                       "[smdp_tls_port=<n>|auto|off] [smds_tls_port=<n>|auto|off] [--tls]",
              "summary": "The background ESipa service (with the local SM-DP+ and SM-DS) other IPAs poll; a card's "
                         "IPAe reaches the eIM on its TLS listener (tls_port, the next port by default), for a "
                         "direct download the SM-DP+ on its own (smdp_tls_port, the port after that), and for an "
                         "Event Retrieval of its own the SM-DS (smds_tls_port, four past the plain port).",
              "examples": ["SERVE start", "SERVE start tls_port=off", "SERVE start smdp_tls_port=off",
                           "SERVE start smds_tls_port=off", "SERVE status", "SERVE restart", "SERVE stop"]},
    "TRAFFIC": {"usage": "TRAFFIC [n] [eid=<eid>] [op=<id>] [after=<id>] [--brief] [--hex] [--json]",
                "summary": "The last n exchanges the service answered (20 by default), oldest first: who asked over "
                           "which chain, what the request said and what the eIM answered, by name and value. "
                           "--brief is one line each, --hex adds the bodies, after= continues from an exchange "
                           "number.",
                "examples": ["TRAFFIC", "TRAFFIC 50 --brief", "TRAFFIC eid=89049032123451234512345678901235",
                             "TRAFFIC op=504 --hex"]},
    "TLS-SETUP": {
        "usage": "TLS-SETUP [list] | NEW <name> [fqdn=<host>] [layout=<stored cert|file>] [ca_layout=<stored cert|file>] "
                 "[registered_id=auto|on|off] [cn=auto|host|keep|eim_id] [chain=self|root|intermediate] [trust=leaf|leaf_key|root|intermediate|"
                 "none] [curve=p256|p384|brainpoolp256r1|ed25519] [san=<name>|none] [validity=valid|expired|"
                 "not_yet_valid] [ski=on|off] [ca_basic_constraints=on|off] [server_auth=on|off] "
                 "[send=leaf|chain|full] [versions=1.2+|1.2|1.3] [ciphers=<openssl list>] "
                 "[client_auth=none|optional|required] [client_ca=<stored cert|file>[,...]] [sni=any|required] "
                 "[--replace] [--force] [--use|--apply] [--yes] | SHOW <name> | USE <name|identity> [--associate] [--yes] "
                 "| CLIENT-CERT <name> [cn=<text>] | REMOVE <name> [--force] | LEAF <name> [LIST] | LEAF <name> NEW <leaf> "
                 "[cn=auto|host|keep|eim_id] [san=<name>|none] [registered_id=auto|on|off] [layout=<stored cert|file>|none] "
                 "[validity=valid|expired|not_yet_valid] [ski=on|off] [server_auth=on|off] "
                 "[curve=p256|p384|brainpoolp256r1|ed25519] [send=leaf|chain|full] [subject=<RFC 4514 name>|none] "
                 "[ext.<extension>=[critical,]<value>|DER:<hex> ...] [extensions=none] [text=<file>] [--replace] [--use] "
                 "| LEAF <name> TEXT <leaf> [out=<new file>] | TEXT <stored cert|file> [out=<new file>] "
                 "| LEAF <name> SHOW <leaf> [--der] | LEAF <name> USE <leaf> [--associate [--yes]] [--serve-only] | LEAF <name> REMOVE <leaf> | "
                 "RESULTS [<name>] [n=<rows>] [--rows] [--json]",
        "summary": "Build a TLS chain for the card-facing listener and pick what AddInitialEim tells the card to "
                   "trust; fqdn= makes the setup stand for an eIM of its own (eimFqdn and the leaf's name), layout= / "
                   "ca_layout= shape the leaf and the CA members after reference certificates, client_auth= turns on "
                   "mutual TLS (client_ca= names the CA the client certificates chain to; CLIENT-CERT issues one under "
                   "the setup's own CA), sni=required answers only a client that names the host. USE serves it (the "
                   "running service restarts), --associate / --apply also re-runs ASSOCIATE so the card trusts it. "
                   "LEAF issues further leaves under the setup's own CA and puts one of them on the setup's name: a card "
                   "that trusts the root or the intermediate meets the next leaf without a new ASSOCIATE; an option left "
                   "out is the setup's own. RESULTS counts the card-facing handshakes per leaf served: accepted (a full "
                   "handshake that a request followed), refused with the client's alert, resumed. A rebuild or a removal "
                   "of a setup that has further leaves or associated cards takes --force. A leaf's subject and "
                   "extensions can be written out: subject= takes an RFC 4514 name, each ext.<extension>= one extension "
                   "in the order given (an RFC 5280 name such as keyUsage, subjectAltName, extKeyUsage, or an object "
                   "identifier with DER:<hex>), extensions=none a leaf without any; {host} and {eim_id} stand for the "
                   "setup's FQDN and the eimId, hash and keyid for the computed key identifiers. What is written is "
                   "built as written and the options decide the rest. TEXT prints a leaf or any certificate in the "
                   "same form (out=<new file> writes it, never over a file), and text=<file> issues from such a file.",
        "examples": ["TLS-SETUP NEW ca-chain chain=intermediate trust=root --apply",
                     "TLS-SETUP NEW other-eim fqdn=eim-other.yggdrasim.local layout=OTHER-EIM-TLS ca_layout=OTHER-ROOT "
                     "chain=root trust=root --use",
                     "TLS-SETUP NEW mtls chain=root trust=root client_auth=required sni=required --use",
                     "TLS-SETUP CLIENT-CERT mtls",
                     "TLS-SETUP NEW no-ski ski=off --use", "TLS-SETUP NEW pinned-key trust=leaf_key",
                     "TLS-SETUP USE identity --associate",
                     "TLS-SETUP LEAF ca-chain NEW cn-eimid cn=eim_id registered_id=on --use",
                     "TLS-SETUP LEAF ca-chain", "TLS-SETUP LEAF ca-chain USE built",
                     "TLS-SETUP LEAF ca-chain NEW two-names ext.keyUsage=critical,digitalSignature "
                     "ext.subjectAltName=DNS:{host},DNS:eim9.yggdrasim.local,RID:{eim_id}",
                     "TLS-SETUP LEAF ca-chain NEW own-subject subject=\"CN={host},OU=Lab,O=Example Org,C=XX\"",
                     "TLS-SETUP LEAF ca-chain TEXT built out=leaf.txt", "TLS-SETUP LEAF ca-chain NEW edited text=leaf.txt",
                     "TLS-SETUP RESULTS ca-chain", "TLS-SETUP RESULTS ca-chain --rows n=20"],
    },
    "DELIVER": {"usage": "DELIVER [--once]",
                "summary": "Act as IPAd on the card in the reader until its queue is empty. The Notifications read "
                           "from the card with a result are acknowledged, so the card drops them, and are then sent "
                           "to the SM-DP+ each names (NOTIFICATIONS lists them).",
                "examples": ["DELIVER", "DELIVER --once"]},
    "INJECT": {"usage": "INJECT [<eid>] [target=http://127.0.0.1:<port>|https://<address>:<port>|none] "
                        "[binding=asn1|json] [timeout=<seconds>] [--once]",
               "summary": "Send an eUICC's queue to its IPA with ESipa.TransferEimPackage (eIM Package Injection, "
                          "SGP.32 v1.3 section 3.1.1.2). The target is the address EIM-LISTEN prints in the eSIM "
                          "Management console; it is kept per eUICC. Plain HTTP on the loopback, or HTTPS on any "
                          "address with the client certificate INJECT-CERT makes; no reader is used.",
               "examples": ["INJECT 89049032123451234512345678901235 target=http://127.0.0.1:8746", "INJECT",
                            "INJECT --once", "INJECT 89049032123451234512345678901235 binding=json",
                            "INJECT 89049032123451234512345678901235 target=https://192.0.2.4:8746",
                            "INJECT 89049032123451234512345678901235 target=none"]},
    "INJECT-CERT": {"usage": "INJECT-CERT",
                    "summary": "Make, once, the client certificate this eIM presents to an IPA that takes "
                               "ESipa.TransferEimPackage over HTTPS, and show where it is. The IPA authenticates the "
                               "eIM by it: name the file as client-ca= of EIM-LISTEN.",
                    "examples": ["INJECT-CERT"]},
    "NOTIFICATIONS": {
        "usage": "NOTIFICATIONS [<eid>] | NOTIFICATIONS SEND [<eid>] [<seqNumber> ...]",
        "summary": "The Notifications IPAs handed to this eIM and where each stands. The eIM sends every one to the "
                   "Notification Receiver its metadata names (ES9+'.HandleNotification, SGP.32 v1.3 section 5.7.4), "
                   "after DELIVER and INJECT and while the service runs, and holds none back; a receiver that is "
                   "down is tried again. One that cannot be delivered (refused, out of attempts, or not sendable as "
                   "it stands) ends as failed. SEND tries the pending ones now, or exactly the ones named (a failed "
                   "or kept one goes again only when named).",
        "examples": ["NOTIFICATIONS", "NOTIFICATIONS 89049032123451234512345678901235", "NOTIFICATIONS SEND",
                     "NOTIFICATIONS SEND 89049032123451234512345678901235 7 9"],
    },
    "EIM-SETTINGS": {"usage": "EIM-SETTINGS [key=value ...]",
                     "summary": "Queue rules: " + ", ".join(SETTING_DEFAULTS) + ".",
                     "examples": ["EIM-SETTINGS", "EIM-SETTINGS learn_unknown_eids=on max_retries=0"]},
    "PACKAGE-IMPORT": {"usage": "PACKAGE-IMPORT <file|folder> [eid] [--plan]",
                       "summary": "Queue the operation(s) an eIM package document (template, hotfolder file) stands for.",
                       "examples": ["PACKAGE-IMPORT Workspace/LocalEIM/eim_packages/templates/"
                                    "template_euicc_package_request_psmos.json",
                                    "PACKAGE-IMPORT Workspace/LocalEIM/eim_packages/hotfolder"]},
    "SMDP-PROFILE": {"usage": "SMDP-PROFILE [list] | SMDP-PROFILE <matchingId> <profilePath> | SMDP-PROFILE <matchingId> -",
                     "summary": "Which profile the local SM-DP+ serves for a Matching ID.",
                     "examples": ["SMDP-PROFILE", "SMDP-PROFILE MID-1 Workspace/LocalEIM/profile/test_profile.txt"]},
    "SMDS": {
        "usage": "SMDS [status] | SMDS LIST [<eid>] | SMDS REGISTER <eid> [<eventId>] [rsp=<address>] "
                 "[type=download|rpm] | SMDS DELETE <eid> <eventId> | SMDS ADDRESS [<fqdn>]",
        "summary": "The local SM-DS: its address and certificate, and the Event Records it holds. REGISTER puts "
                   "one on file for an eUICC (the EventID is the Matching ID the SM-DP+ at rsp= will be asked "
                   "for; without rsp= that is the local SM-DP+, without an EventID one is made up). A download "
                   "queued with contact_smds=on retrieves the records of its eUICC; the local SM-DP+ deletes a "
                   "record when the download it led to ends. ADDRESS changes the name the SM-DS answers under "
                   "and restarts a running service. No verb opens a reader.",
        "examples": ["SMDS", "SMDS REGISTER 89049032123451234512345678901235 MID-1",
                     "SMDS REGISTER 89049032123451234512345678901235 EVENT-7 rsp=smdpp.example.test",
                     "SMDS LIST 89049032123451234512345678901235",
                     "SMDS DELETE 89049032123451234512345678901235 MID-1", "SMDS ADDRESS smds.example.test"],
    },
}

HELP_SECTIONS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    ("Operations (queue)", (
        ("QUEUE <operation> [eid] [value] [k=v]", "QUEUE"),
        ("OPS [pending|completed|all]", "OPS"),
        ("OP <id> [--decode]", "OP"),
        ("EDIT <id> k=v ...", "EDIT"),
        ("MOVE <id> first|last|up|down", "MOVE"),
        ("CANCEL <id>", "CANCEL"),
        ("COPY <id> [k=v ...]", "COPY"),
        ("EXPORT <id>", "EXPORT"),
        ("RESULT <id> <hex>", "RESULT"),
        ("PACKAGE-IMPORT <file|folder> [eid]", "PACKAGE-IMPORT"),
    )),
    ("eUICCs, Identity & Delivery", (
        ("EUICC [list|<eid>|ADD|READ|SET|REMOVE]", "EUICC"),
        ("IDENTITY [show|NEW|IMPORT]", "IDENTITY"),
        ("ASSOCIATE [setup=<name>|CHOICES|HANDOVER ...]", "ASSOCIATE"),
        ("TLS-SETUP [list|NEW|SHOW|USE|REMOVE]", "TLS-SETUP"),
        ("SERVE [status|start|stop|restart]", "SERVE"),
        ("TRAFFIC [n] [eid=] [op=] [--brief|--hex]", "TRAFFIC"),
        ("DELIVER [--once]", "DELIVER"),
        ("INJECT [<eid>] [target=<url>] [--once]", "INJECT"),
        ("INJECT-CERT", "INJECT-CERT"),
        ("NOTIFICATIONS [<eid>|SEND]", "NOTIFICATIONS"),
        ("EIM-SETTINGS [k=v ...]", "EIM-SETTINGS"),
        ("SMDP-PROFILE [list|<mid> <path>]", "SMDP-PROFILE"),
        ("SMDS [status|LIST|REGISTER|DELETE|ADDRESS]", "SMDS"),
    )),
)


def _split(argument: str) -> tuple[list[str], dict[str, str], dict[str, str]]:
    """Return (positional, key=value, --flags with their values)."""
    try:
        tokens = shlex.split(argument)
    except ValueError as error:
        raise LocalEimError(f"Cannot read the arguments: {error}") from error
    positional: list[str] = []
    pairs: dict[str, str] = {}
    flags: dict[str, str] = {}
    takes_value = {"--at", "--retries", "--fault", "--eid-file", "--raw"}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("--"):
            name = token.lower()
            if name in takes_value:
                if index + 1 >= len(tokens):
                    raise LocalEimError(f"{token} needs a value.")
                flags[name] = tokens[index + 1]
                index += 2
                continue
            flags[name] = "1"
        elif "=" in token and not token.startswith("1$"):
            key, value = token.split("=", 1)
            pairs[key.strip().lower()] = value
        else:
            positional.append(token)
        index += 1
    return positional, pairs, flags


def _looks_like_eid(text: str) -> bool:
    digits = "".join(str(text).split())
    return len(digits) == 32 and digits.isdigit()


# What a verb refuses with: printed as one line, the shell keeps running.
_REFUSALS = (LocalEimError, OperationError, StoreError, IdentityError, ServiceError, SmdpError, SmdsError,
             DeliveryError, InjectError, codec.CodecError, ValueError, ReaderBusyError)

def _no_card_errors() -> tuple[type[BaseException], ...]:
    """What opening the card channel raises when no reader or no card is there."""
    try:
        from smartcard.Exceptions import SmartcardException
    except ImportError:  # no pyscard: the channel is not a PC/SC one
        return (OSError, RuntimeError)
    return (OSError, RuntimeError, SmartcardException)


def _decoder_reading(hex_text: str) -> list[str]:
    """The Decoder's reading of an ESipa package or result in the ES10 context (SGP.22 / SGP.32), as lines.

    The eIM's own rows name what it acts on; the Decoder reads every data object
    of the compiled schema, so a member the eIM does not keep still shows.
    """
    try:
        from Tools.Asn1TlvDecode.context import decode_context_hex, render_context_notation
    except ImportError as error:
        return [f"[*] The Decoder is not available here: {error}"]
    try:
        return render_context_notation(decode_context_hex(hex_text, hint="es10")).splitlines()
    except ValueError as error:
        return [f"[*] The Decoder did not read it: {error}"]


class EngineVerbs:
    """The queue verbs bound to one EimLocalShell."""

    def __init__(self, shell: Any, *, emit: Callable[[str], None] = print) -> None:
        self.shell = shell
        self.emit = emit
        self._engine: LocalEim | None = None
        # A caller that closes the card channel itself after a verb sets this and runs
        # forward_due_notifications once the channel is closed.
        self.defer_notification_pass = False

    @property
    def engine(self) -> LocalEim:
        if self._engine is None:
            self._engine = LocalEim()
        return self._engine

    # -- registration -------------------------------------------------

    def install(self) -> None:
        commands = {
            "QUEUE": self.cmd_queue,
            "OPS": self.cmd_ops,
            "OP": self.cmd_op,
            "EDIT": self.cmd_edit,
            "MOVE": self.cmd_move,
            "CANCEL": self.cmd_cancel,
            "COPY": self.cmd_copy,
            "EXPORT": self.cmd_export,
            "RESULT": self.cmd_result,
            "EUICC": self.cmd_euicc,
            "IDENTITY": self.cmd_identity,
            "ASSOCIATE": self.cmd_associate,
            "TLS-SETUP": self.cmd_tls_setup,
            "SERVE": self.cmd_serve,
            "TRAFFIC": self.cmd_traffic,
            "DELIVER": self.cmd_deliver,
            "INJECT": self.cmd_inject,
            "INJECT-CERT": self.cmd_inject_cert,
            "NOTIFICATIONS": self.cmd_notifications,
            "EIM-SETTINGS": self.cmd_settings,
            "SMDP-PROFILE": self.cmd_smdp_profile,
            "SMDS": self.cmd_smds,
            "PACKAGE-IMPORT": self.cmd_package_import,
        }
        for name, handler in commands.items():
            self.shell._commands[name] = self._guarded(handler)
        self.shell._command_docs.update(DOCS)

    def run(self, verb: str, argument: str = "") -> bool:
        """Run one verb with its refusals printed, the way the shell runs it; False when it was refused."""
        try:
            getattr(self, f"cmd_{verb}")(argument)
        except _REFUSALS as error:
            self.emit(f"[!] {error}")
            return False
        return True

    def _guarded(self, handler: Callable[[str], None]) -> Callable[[str], None]:
        def run(argument: str = "") -> None:
            try:
                handler(argument)
            except _REFUSALS as error:
                self.emit(f"[!] {error}")
        run.__name__ = getattr(handler, "__name__", "run")
        run.__doc__ = handler.__doc__
        return run

    # -- card access --------------------------------------------------

    def _ensure_channel(self) -> None:
        """Open the card channel LocalIsdrSession would have built: a named remote reader, else PC/SC."""
        session = self.shell.session
        if getattr(session, "no_reader", False):
            # A caller that claimed no reader for this run (a GUI action that named its eUICC).
            raise LocalEimError("This call was given no reader, so it reads no card. Name the eUICC by its EID "
                                "(32 digits).")
        if getattr(session, "apdu_channel", None) is None:
            remote = str(getattr(session.cfg, "READER_NAME", "") or "").strip()
            if remote:
                from SCP11.transport import RemoteApduChannel

                session.apdu_channel = RemoteApduChannel(remote)
            else:
                from SCP11.transport import PcscApduChannel

                session.apdu_channel = PcscApduChannel(reader_index=int(getattr(session.cfg, "READER_INDEX", 0)))
        self._declare_ipad()

    def _declare_ipad(self) -> None:
        """TERMINAL CAPABILITY with tag '84' b1 set, once per card session and again after a reset.

        SGP.32 v1.3 §3.8.2 has the eUICC enable the ES10 functions only after
        the IoT Device declares IPAd support, and a reset clears the
        declaration: a live eUICC answered 6985 to every ES10 command after the
        reset that completes a Profile state change until this was sent. A
        card that takes no TERMINAL CAPABILITY is noted, not refused. The
        session's own SELECT declares through the same helper, so the card
        session gets one declaration whichever comes first.
        """
        note = declare_ipad(self.shell.session.apdu_channel, "EIM-LOCAL: TERMINAL CAPABILITY (IPAd)")
        if len(note) > 0:
            self.emit(f"[*] {note}")

    def _exchange(self, payload: bytes, label: str) -> bytes:
        self._ensure_channel()
        return self.shell.session.exchange_isdr_command(payload, label, sync_notifications=False)

    def _reset_card(self) -> bool:
        """Reset the card behind the session channel; False when the channel has no reset or it failed."""
        try:
            from smartcard.Exceptions import SmartcardException
        except ImportError:  # no pyscard: the channel is not a PC/SC one
            SmartcardException = OSError  # noqa: N806 - stands in for the pyscard class
        channel = getattr(self.shell.session, "apdu_channel", None)
        reset = getattr(channel, "reset", None)
        if not callable(reset):
            return False
        try:
            done = bool(reset())
        except (OSError, RuntimeError, SmartcardException) as error:
            self.emit(f"[*] card reset failed ({error}); the Notifications follow with a later package")
            return False
        self.shell.session.reset_state()
        if done:
            # The reset cleared the IPAd declaration with the rest of the card session.
            forget_ipad_declaration(channel)
            self._declare_ipad()
        return done

    def _card_eid(self) -> str:
        """The EID of the card in the reader, read while this shell holds the reader.

        Opening the channel power-cycles the card, so it happens behind the
        reader lock as every other card verb does: a reader that runs
        EIM-LISTEN, a poll or the HIL bridge refuses it at once instead of
        losing its card session.
        """
        def read() -> str:
            self._ensure_channel()
            return str(self.shell.session._read_card_eid_safe() or "")

        eid = self._with_reader("EID read", read)
        if len(eid) == 0:
            raise LocalEimError("No EID given and none read from a card; name the EID.")
        return codec.normalize_eid(eid)

    def _unnamed_eid(self) -> str:
        """The eUICC of a verb that names none and needs no card itself (QUEUE, PACKAGE-IMPORT).

        The card in the reader comes first, as it always did. When the reader
        is held or no card answers, the one eUICC that has an inject target is
        taken and said: that is the eUICC whose IPA is being called. A kept
        target never wins over a card that can be read.
        """
        if getattr(self.shell.session, "no_reader", False):
            # No card and no guess either: the caller said which eUICC it meant, and it did not read as one.
            raise LocalEimError("No EID was given that reads as one (32 digits), and this call was given no "
                                "reader to read it from a card.")
        try:
            return self._card_eid()
        except ReaderBusyError as busy:
            reason = str(busy)
        except LocalEimError:
            reason = "no EID was read from a card"
        except _no_card_errors() as error:
            reason = f"no card answered ({type(error).__name__}: {error})"
        with_target = [record.eid for record in self.engine.records() if self.engine.inject_target(record.eid)]
        if len(with_target) != 1:
            which = "no eUICC has an inject target" if not with_target else "more than one eUICC has an inject target"
            raise LocalEimError(f"No EID given; {reason}, and {which}. Name the EID.")
        self.emit(f"[*] No EID given; {reason}. Taking the eUICC that has an inject target: {with_target[0]}")
        return with_target[0]

    def _reader_name(self) -> str:
        from yggdrasim_common.card_backend import is_simulated_card_backend

        if is_simulated_card_backend():
            return ""
        cfg = self.shell.session.cfg
        if len(str(getattr(cfg, "READER_NAME", "") or "").strip()) > 0:
            return ""
        try:
            from smartcard.System import readers as list_pcsc_readers

            found = list(list_pcsc_readers() or [])
            index = int(getattr(cfg, "READER_INDEX", 0))
        except Exception:  # noqa: BLE001 - no PC/SC: nothing to hold, the card access reports the fault
            return ""
        return str(found[index]) if 0 <= index < len(found) else ""

    def _with_reader(self, verb: str, body: Callable[[], Any]) -> Any:
        from yggdrasim_common import reader_locks

        reader = self._reader_name()
        hold = reader_locks.acquire(
            reader, f"{verb} in the eIM-local console",
            on_wait=lambda other: self.emit(f"[*] {verb}: waiting for the reader, held by "
                                            f"{other.describe() if other else 'another process'}."),
        )
        try:
            return body()
        finally:
            hold.release()

    # -- output -------------------------------------------------------

    def _print_operation_line(self, operation: Any) -> None:
        kind = OPERATION_TYPES.get(operation.type)
        from SCP11.eim_local.engine.catalogue import describe as describe_operation

        text = describe_operation(kind, operation.params) if kind else operation.type
        when = (operation.finished_at or operation.served_at or operation.created_at or "")[:19]
        marks = " system" if operation.system else ""
        self.emit(f"  {operation.id:>5}  {operation.state:<15} {operation.eid[-8:]}  {when}  {text}{marks}")
        for warning in operation.warnings:
            self.emit(f"         ! {warning}")

    # -- verbs --------------------------------------------------------

    def cmd_queue(self, argument: str = "") -> None:
        """QUEUE <operation> [eid] [value] [key=value ...]."""
        positional, pairs, flags = _split(argument)
        if not positional:
            raise LocalEimError("Usage: " + DOCS["QUEUE"]["usage"])
        verb = positional.pop(0).upper()
        eids = self._target_eids(positional, flags)
        if verb == "REFRESH":
            types = list(REFRESH_TYPES)
            values: list[dict[str, Any]] = [{} for _ in types]
        else:
            if verb in QUEUE_VERBS:
                type_name = QUEUE_VERBS[verb]
            else:
                type_name = operation_type(verb).name
            params = dict(pairs)
            if positional:
                slot = POSITIONAL.get(type_name)
                if slot is None:
                    raise LocalEimError(f"{verb} takes no value; got {' '.join(positional)}.")
                params[slot] = " ".join(positional) if slot in ("items", "tags") else positional[0]
            if type_name == "SET_FALLBACK_ATTRIBUTE" and "--unset" in flags:
                type_name = "UNSET_FALLBACK_ATTRIBUTE"
                params.pop("iccid", None)
            types = [type_name]
            values = [params]
        requests = [
            OperationRequest(
                eid=eid, type=type_name, params=dict(params), raw_items=flags.get("--raw", ""),
                not_before=flags.get("--at"),
                max_retries=int(flags["--retries"]) if "--retries" in flags else None,
                fault=flags.get("--fault", ""),
            )
            for eid in eids
            for type_name, params in zip(types, values)
        ]
        if "--plan" in flags:
            for entry in self.engine.plan(requests):
                self.emit(f"[plan] {entry.eid}  {entry.type}: {entry.description}")
                self.emit(f"       bytes fixed now: {entry.preview_hex or '-'}")
                for warning in entry.warnings:
                    self.emit(f"       ! {warning}")
            return
        created = self.engine.submit(requests, author="eim-local shell", first="--first" in flags)
        self.emit(f"[+] Queued {len(created)} operation(s), task {created[0].task_id}:")
        for operation in created:
            self._print_operation_line(operation)

    def _target_eids(self, positional: list[str], flags: dict[str, str]) -> list[str]:
        if "--eid-file" in flags:
            with open(flags["--eid-file"], encoding="utf-8") as handle:
                eids = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
            return [codec.normalize_eid(eid) for eid in eids]
        if positional and _looks_like_eid(positional[0]):
            return [codec.normalize_eid(positional.pop(0))]
        return [self._unnamed_eid()]

    def cmd_ops(self, argument: str = "") -> None:
        """OPS [pending|completed|all] [eid=] [type=] [limit=]."""
        positional, pairs, flags = _split(argument)
        scope = (positional[0].lower() if positional else "pending")
        states = {"pending": ("CREATED", "SENT"),
                  "completed": ("SUCCESS", "PARTIAL_SUCCESS", "ERROR", "CANCELED"),
                  "all": ()}.get(scope)
        if states is None:
            raise LocalEimError("OPS takes pending, completed or all.")
        operations = self.engine.operations(
            eid=pairs.get("eid", ""), states=states,
            types=(operation_type(pairs["type"]).name,) if pairs.get("type") else (),
            limit=int(pairs.get("limit", "50")),
        )
        if "--json" in flags:
            self.emit(json.dumps([vars(entry) for entry in operations], indent=2, default=str))
            return
        self.emit(f"[*] {scope.capitalize()} operations ({len(operations)}):")
        self.emit("     id  state           EID       when                 description")
        for operation in operations:
            self._print_operation_line(operation)

    def cmd_op(self, argument: str = "") -> None:
        positional, _pairs, flags = _split(argument)
        if not positional:
            raise LocalEimError("Usage: OP <id>")
        operation = self.engine.operation(int(positional[0]))
        if "--json" in flags:
            self.emit(json.dumps(vars(operation), indent=2, default=str))
            return
        self.emit(f"[*] Operation {operation.id} ({operation.type}) for {operation.eid}: {operation.state}")
        shown = {key: ("***" if key == "confirmation_code" else value) for key, value in operation.params.items()}
        self.emit(f"    parameters : {json.dumps(shown)}")
        if operation.raw_items:
            self.emit(f"    raw items  : {operation.raw_items}")
        self.emit(f"    transaction: {operation.transaction_id}  counter: {operation.counter_value}  "
                  f"retries: {operation.retries}/{operation.max_retries}  route: {operation.route or '-'}")
        if operation.not_before:
            self.emit(f"    not before : {operation.not_before}")
        if operation.fault:
            self.emit(f"    fault      : {operation.fault}")
        for warning in operation.warnings:
            self.emit(f"    warning    : {warning}")
        if operation.flags:
            self.emit(f"    flags      : {', '.join(operation.flags)}")
        if operation.error:
            self.emit(f"    error      : {operation.error}")
        self.emit("    timeline:")
        for event in operation.history:
            self.emit(f"      {event.get('at', '')[:19]}  {event.get('event', '')}")
        if operation.served_hex:
            self.emit(f"    served     : {operation.served_hex}")
            for row in traffic.describe_package(bytes.fromhex(operation.served_hex)):
                self.emit(f"      {row.tag:<5} {row.name:<30} {row.value}".rstrip())
        if operation.result_hex:
            self.emit(f"    result     : {operation.result_hex}")
            for row in traffic.describe_result(bytes.fromhex(operation.result_hex)):
                self.emit(f"      {row.tag:<5} {row.name:<30} {row.value}".rstrip())
        for line in operation.result.get("items", []) if isinstance(operation.result, dict) else []:
            self.emit(f"      {line}")
        if "--decode" in flags:
            for label, hex_text in (("served package", operation.served_hex), ("result", operation.result_hex)):
                if hex_text:
                    self.emit(f"    Decoder reading of the {label}:")
                    for line in _decoder_reading(hex_text):
                        self.emit(f"      {line}")

    def cmd_traffic(self, argument: str = "") -> None:
        """TRAFFIC [n] [eid=<eid>] [op=<id>] [after=<id>] [--brief] [--hex] [--json]."""
        positional, pairs, flags = _split(argument)
        try:
            limit = int(positional[0]) if positional else 20
            operation_id = int(pairs["op"]) if pairs.get("op") else None
            after_id = int(pairs["after"]) if pairs.get("after") else None
        except ValueError as error:
            raise LocalEimError(f"TRAFFIC takes numbers for n, op= and after=: {error}") from error
        eid = codec.normalize_eid(pairs["eid"]) if pairs.get("eid") else ""
        records = self.engine.store.traffic(limit=max(1, limit), eid=eid, operation_id=operation_id,
                                            after_id=after_id, newest_first=after_id is None)
        if after_id is None:
            records.reverse()
        if "--json" in flags:
            self.emit(json.dumps([{**vars(record), "request": record.request.hex().upper(),
                                   "response": record.response.hex().upper(),
                                   "summary": traffic.describe_record(record).summary} for record in records],
                                 indent=2, default=str))
            return
        if not records:
            self.emit("[*] No exchanges recorded. The service records every request it answers; SERVE status says "
                      "whether it runs.")
            return
        self.emit(f"[*] {len(records)} exchange(s), oldest first:")
        for record in records:
            view = traffic.describe_record(record)
            self.emit("    " + traffic.summary_line(record, view))
            if "--brief" in flags:
                continue
            for line in traffic.rows_as_text(view, hex_bodies="--hex" in flags):
                self.emit(line)

    def cmd_edit(self, argument: str = "") -> None:
        positional, pairs, _flags = _split(argument)
        if not positional or not pairs:
            raise LocalEimError("Usage: " + DOCS["EDIT"]["usage"])
        changes: dict[str, Any] = {}
        for key, value in pairs.items():
            name = {"raw": "raw_items", "at": "not_before", "retries": "max_retries"}.get(key, key)
            changes[name] = value
        operation = self.engine.edit(int(positional[0]), changes)
        self.emit(f"[+] Operation {operation.id} edited: {operation.history[-1]['event']}")
        self._print_operation_line(operation)

    def cmd_move(self, argument: str = "") -> None:
        positional, _pairs, _flags = _split(argument)
        if len(positional) < 2:
            raise LocalEimError("Usage: " + DOCS["MOVE"]["usage"])
        other = int(positional[2]) if len(positional) > 2 else None
        order = self.engine.move(int(positional[0]), positional[1], other)
        self.emit("[+] Queue order: " + ", ".join(str(entry.id) for entry in order))

    def cmd_cancel(self, argument: str = "") -> None:
        positional, pairs, _flags = _split(argument)
        if pairs.get("eid"):
            canceled = self.engine.cancel_eid(pairs["eid"])
            self.emit(f"[+] Canceled {len(canceled)} queued operation(s).")
            return
        if not positional:
            raise LocalEimError("Usage: " + DOCS["CANCEL"]["usage"])
        operation = self.engine.cancel(int(positional[0]))
        self.emit(f"[+] Operation {operation.id}: {operation.history[-1]['event']}")

    def cmd_copy(self, argument: str = "") -> None:
        positional, pairs, _flags = _split(argument)
        if not positional:
            raise LocalEimError("Usage: " + DOCS["COPY"]["usage"])
        operation = self.engine.copy(int(positional[0]), dict(pairs) or None, author="eim-local shell")
        self.emit(f"[+] Queued operation {operation.id} as a copy of {positional[0]}.")
        self._print_operation_line(operation)

    def cmd_export(self, argument: str = "") -> None:
        positional, _pairs, _flags = _split(argument)
        if not positional:
            raise LocalEimError("Usage: EXPORT <id>")
        package, steps = self.engine.export(int(positional[0]))
        self.emit(f"[+] eIM Package ({len(package)} bytes): {package.hex().upper()}")
        self.emit("[+] STORE DATA script:")
        for step in steps:
            self.emit(f"    {step.apdu_hex}    # {step.label}")
        self.emit("[*] Paste the card's answer back with RESULT <id> <hex>.")

    def cmd_result(self, argument: str = "") -> None:
        positional, _pairs, _flags = _split(argument)
        if len(positional) < 2:
            raise LocalEimError("Usage: RESULT <id> <hex>")
        accepted = self.engine.import_result(int(positional[0]), "".join(positional[1:]))
        for message in accepted.messages:
            self.emit(f"[+] {message}")
        if accepted.acknowledgements:
            self.emit(f"[*] Acknowledge on the card: RemoveNotificationFromList {accepted.acknowledgements}")

    def cmd_euicc(self, argument: str = "") -> None:
        positional, pairs, _flags = _split(argument)
        action = positional[0].upper() if positional else "LIST"
        if action == "LIST":
            records = self.engine.records()
            self.emit(f"[*] eUICCs ({len(records)}):")
            for record in records:
                pending = len(self.engine.queue(record.eid))
                profiles = ", ".join(
                    f"{entry.get('iccid', '?')}({entry.get('state', '?')[0]})" for entry in record.profiles
                ) or "-"
                self.emit(f"  {record.eid}  {record.label or '-'}  pending {pending}  "
                          f"last poll {(record.last_poll_at or '-')[:19]}  profiles {profiles}")
            return
        if action == "ADD":
            record = self.engine.register(positional[1], label=" ".join(positional[2:]))
            self.emit(f"[+] Registered {record.eid}.")
            return
        if action == "READ":
            reads = self._with_reader("EUICC READ", lambda: read_card(self._exchange))
            record = self.engine.apply_card_reads(str(reads["eid"]), reads)
            self.emit(f"[+] {record.eid}: {len(record.profiles)} profile(s), {len(record.eims)} eIM(s), "
                      f"certificate read.")
            return
        if action == "SET":
            record = self.engine.update_record(positional[1], pairs)
            self.emit(f"[+] {record.eid}: token {record.association_token}, counter {record.counter_value}, "
                      f"seqNumber {record.seq_number}")
            return
        if action == "REMOVE":
            removed = self.engine.remove(positional[1])
            self.emit(f"[+] Removed {removed} record(s) and their operations.")
            return
        record = self.engine.record(positional[0])
        if record is None:
            raise LocalEimError(f"No eUICC {positional[0]}.")
        self.emit(f"[*] eUICC {record.eid} {record.label}")
        self.emit(f"    associationToken {record.association_token}  counter {record.counter_value}  "
                  f"seqNumber {record.seq_number}  certificate {'yes' if record.euicc_certificate else 'no'}")
        self.emit(f"    associated {record.data.get('associated', '?')}  default SM-DP+ "
                  f"{record.data.get('default_smdp_address', '-')}  immediate enable "
                  f"{record.data.get('immediate_enable', '-')}"
                  + (f"  rPLMN {record.data['rplmn_hex']}" if record.data.get("rplmn_hex") else ""))
        for entry in record.profiles:
            self.emit(f"    profile {entry.get('iccid')}  {entry.get('state')}  {entry.get('class', '')}"
                      f"{'  fallback' if entry.get('fallback') else ''}  {entry.get('name', '')}")
        for entry in record.eims:
            self.emit(f"    eIM {entry.get('eim_id')}  {entry.get('eim_id_type', '')}")
        target = self.engine.inject_target(record.eid)
        if target is not None:
            self.emit(f"    inject target {target['url']}  ({target['binding']} binding)")
        for key, value in sorted(record.data.get("refreshed", {}).items()):
            self.emit(f"    refreshed {key}: {value}")
        self.emit("    queue:")
        for operation in self.engine.queue(record.eid):
            self._print_operation_line(operation)

    def cmd_identity(self, argument: str = "") -> None:
        positional, pairs, _flags = _split(argument)
        action = positional[0].upper() if positional else "SHOW"
        if action == "NEW":
            identity = self.engine.new_identity(
                eim_id=positional[1] if len(positional) > 1 else "",
                eim_fqdn=positional[2] if len(positional) > 2 else "",
            )
        elif action == "IMPORT":
            identity = self.engine.import_identity(
                eim_id=pairs["eim_id"], eim_fqdn=pairs.get("fqdn", ""), signing_key_path=pairs["key"],
                signing_certificate_path=pairs["cert"], tls_key_path=pairs.get("tls_key", ""),
                tls_certificate_path=pairs.get("tls_cert", ""),
            )
        else:
            identity = self.engine.identity()
        for key, value in identity.describe().items():
            self.emit(f"    {key:<32} {value}")
        self.emit(f"    store                            {store_directory()}")

    def cmd_associate(self, argument: str = "") -> None:
        positional, pairs, flags = _split(argument)
        action = positional[0].upper() if positional else ""
        if action in ("CHOICES", "LIST"):
            self._associate_choices()
            return
        if action == "HANDOVER":
            self._associate_handover(pairs, flags)
            return
        if positional:
            raise LocalEimError("Usage: " + DOCS["ASSOCIATE"]["usage"])
        identity = self.engine.identity()
        key_form = "public_key" if "--public-key" in flags else "certificate"
        # The live-name check comes before any card access: the setup asked for, or the one in use, is known
        # without the card; a setup remembered for the card is checked again once its EID is read.
        early = self.engine.association_configuration(
            key_form=key_form, setup=pairs.get("setup") or tls_setup.active_name(self.engine.directory) or None,
            fqdn=pairs.get("fqdn"),
        )
        check_association_name(early)
        eid = self._card_eid()
        name = self.engine.association_setup(eid, pairs.get("setup"))
        record = self.engine.record(eid)
        if pairs.get("setup") is not None:
            source = "asked for"
        elif record is not None and record.data.get("tls_setup"):
            source = "remembered for this card"
        else:
            source = "the one in use"
        configuration = self.engine.association_configuration(key_form=key_form, setup=name, fqdn=pairs.get("fqdn"))
        fqdn = configuration.eim_fqdn or ""
        check_association_name(configuration)
        self._ensure_setup_served(name)
        if not self._confirm_reset(flags, eid, f"adds {identity.eim_id} (eimFqdn {fqdn or '-'}) with AddInitialEim"):
            self.emit("[*] Not associated.")
            return
        self.emit(f"[*] TLS setup {name or 'identity'} ({source}); eimFqdn {fqdn or '-'} "
                  f"({tls_setup.fqdn_source(self.engine.directory, name)}); trustedPublicKeyDataTls: "
                  f"{self._tls_trust_text(name)}")
        lines = self._with_reader("ASSOCIATE", lambda: self.engine.associate(
            self._exchange, eid, reset_first="--no-reset" not in flags, key_form=key_form, setup=name,
            fqdn=pairs.get("fqdn"),
        ))
        for line in lines:
            self.emit(f"[+] {line}")

    def _ensure_setup_served(self, name: str) -> None:
        """A running service serves every setup built before it started; a newer one takes a restart."""
        status = describe()
        if not status.get("running") or not status.get("tls_url"):
            return
        label = name or "identity"
        if label in list(status.get("tls_setups_served") or []):
            return
        restarted = restart_background()
        if restarted is not None and restarted.get("tls_url"):
            self.emit(f"[+] Service restarted so the card-facing listener also serves {label}.")

    def _confirm_reset(self, flags: dict[str, str], eid: str, what: str) -> bool:
        """The EID-digit confirmation every eIM reset of a card takes; ``--yes`` skips it."""
        if "--yes" in flags:
            return True
        self.emit(f"[!] This resets the eIM configuration of {eid} (eUICCMemoryReset resetEimConfigData + "
                  f"resetImmediateEnableConfig) and {what}. Every other eIM is removed from the card.")
        try:
            answer = input(f"    Type the last 8 digits of the EID ({eid[-8:]}) to continue: ").strip()
        except EOFError:
            answer = ""
        return answer == eid[-8:]

    def _tls_trust_text(self, name: str | None = None) -> str:
        resolved = tls_setup.active_name(self.engine.directory) if name is None else name
        if len(resolved) == 0:
            return "the identity's TLS certificate" if self.engine.identity().tls_certificate_path else "none"
        setup = tls_setup.load_setup(self.engine.directory, resolved)
        return f"TLS setup {resolved} ({setup.trust})"

    def _associate_choices(self) -> None:
        """What ASSOCIATE can carry: the identity, every TLS setup, and the stored certificates HANDOVER takes."""
        from SCP11.shared.eim_builder_store import certificates_dir, list_certificates

        directory = self.engine.directory
        identity = self.engine.identity_or_none()
        active = tls_setup.active_name(directory)
        cards: dict[str, list[str]] = {}
        for record in self.engine.records():
            remembered = str(record.data.get("tls_setup", "") or "")
            if remembered:
                cards.setdefault(remembered, []).append(record.eid[-8:])
        self.emit("[*] ASSOCIATE carries the identity's signing key (--public-key: the bare key) and the eIM FQDN and "
                  "TLS trust of a TLS setup: the one asked for (setup=<name>), else the one the card was associated "
                  "with before (cards), else the one in use (*). The listener serves every setup by server name.")
        if identity is None:
            self.emit("    identity: none yet (IDENTITY NEW)")
        else:
            marker = "*" if len(active) == 0 else " "
            held = cards.get("identity", [])
            self.emit(f"  {marker} {'identity':<24} FQDN {identity.eim_fqdn or '-'}  eimId {identity.eim_id}  "
                      f"trusts {'its own TLS certificate' if identity.tls_certificate_path else 'none'}"
                      + (f"  cards ..{', ..'.join(held)}" if held else ""))
        setups = tls_setup.list_setups(directory)
        for setup in setups:
            marker = "*" if setup.name == active else " "
            shaped = []
            if setup.layout:
                shaped.append(f"layout {setup.layout}")
            if setup.ca_layout:
                shaped.append(f"CA layout {setup.ca_layout}")
            held = cards.get(setup.name, [])
            self.emit(f"  {marker} {setup.name:<24} FQDN {setup.effective_fqdn or '-'}  trusts {setup.trust}  "
                      f"chain {setup.chain}" + (f"  ({', '.join(shaped)})" if shaped else "")
                      + (f"  cards ..{', ..'.join(held)}" if held else ""))
        by_name: dict[str, list[str]] = {}
        for setup in setups:
            if setup.effective_fqdn:
                by_name.setdefault(setup.effective_fqdn.lower(), []).append(setup.name)
        for name, owners in sorted(by_name.items()):
            if len(owners) > 1:
                self.emit(f"[!] {name} is the FQDN of {', '.join(owners)}: the listener answers it with "
                          f"{'the one in use' if active in owners else owners[0]}; REMOVE the ones not meant.")
        entries, problems = list_certificates()
        self.emit(f"[*] Stored certificates for ASSOCIATE HANDOVER sign= / tls= (and for layout=), {certificates_dir()}:")
        if len(entries) == 0:
            self.emit("    none (EIM-CERT-STORE IMPORT in the eSIM Live shell, or the eIM certificate store action)")
        for entry in entries:
            self.emit(f"    {entry.name:<40} {entry.summary()}")
        for problem in problems:
            self.emit(f"    [!] {problem}")

    def _associate_handover(self, pairs: dict[str, str], flags: dict[str, str]) -> None:
        """AddInitialEim with another eIM's stored certificates: the card is handed to that eIM."""
        from SCP11.shared.eim_builder_store import EimBuilderStoreError, read_certificate
        from SCP11.shared.eim_configuration_data import (
            EIM_ID_TYPE_NAMES,
            EIM_ID_TYPES,
            EIM_SUPPORTED_PROTOCOL_BITS,
            KEY_FORM_CERTIFICATE,
            KEY_FORM_PUBLIC_KEY,
            EimConfigurationData,
            KeyData,
            infer_eim_id_type,
        )

        eim_id = pairs.get("eim_id", "").strip()
        sign = pairs.get("sign", "").strip()
        if len(eim_id) == 0 or len(sign) == 0:
            raise LocalEimError("ASSOCIATE HANDOVER needs eim_id=<id> and sign=<stored certificate>; "
                                "ASSOCIATE CHOICES lists the store.")

        def stored(name: str) -> Any:
            try:
                return read_certificate(name)
            except EimBuilderStoreError as error:
                raise LocalEimError(str(error)) from error

        signer = stored(sign)
        sign_form = KEY_FORM_PUBLIC_KEY if "--public-key" in flags else KEY_FORM_CERTIFICATE
        sign_key = KeyData(form=sign_form, der=signer.spki_der if sign_form == KEY_FORM_PUBLIC_KEY else signer.der)
        tls_name = pairs.get("tls", "").strip()
        tls_key: KeyData | None = None
        tls_form = KEY_FORM_PUBLIC_KEY if "--tls-key" in flags else KEY_FORM_CERTIFICATE
        if len(tls_name) > 0 and tls_name.lower() != "none":
            trusted = stored(tls_name)
            tls_key = KeyData(form=tls_form, der=trusted.spki_der if tls_form == KEY_FORM_PUBLIC_KEY else trusted.der)
        type_text = pairs.get("eim_id_type", "").strip().lower()
        if len(type_text) > 0:
            id_type = {"oid": 1, "fqdn": 2, "proprietary": 3}.get(type_text)
            if id_type is None:
                raise LocalEimError("eim_id_type is oid, fqdn or proprietary.")
        else:
            id_type = infer_eim_id_type(eim_id)
        fqdn = pairs.get("fqdn", "").strip()
        if id_type == EIM_ID_TYPES["eimIdTypeFqdn"]:
            fqdn = ""
        try:
            counter = int(pairs.get("counter", "0"), 0)
        except ValueError as error:
            raise LocalEimError(f"counter is an integer, not {pairs.get('counter')!r}.") from error
        ci_text = pairs.get("ci_pkid", "").strip()
        ci_pkid: bytes | None = None
        if ci_text.lower() == "card":
            pkids = self._with_reader("ASSOCIATE HANDOVER", lambda: read_signing_ci_pkids(self._exchange))
            if len(pkids) == 0:
                raise LocalEimError("The card lists no CI Public Key Identifier for signing (EUICCInfo1).")
            ci_pkid = pkids[0]
        elif len(ci_text) > 0:
            try:
                ci_pkid = bytes.fromhex(ci_text)
            except ValueError as error:
                raise LocalEimError(f"ci_pkid is hex octets or 'card', not {ci_text!r}.") from error
        indirect_text = pairs.get("indirect", "off").strip().lower()
        if indirect_text not in ("on", "off", "yes", "no", "true", "false", "1", "0"):
            raise LocalEimError("indirect is on or off.")
        indirect = indirect_text in ("on", "yes", "true", "1")
        protocols = tuple(item.strip() for item in pairs.get("protocols", "eimRetrieveHttps").split(",") if item.strip())
        unknown = [item for item in protocols if item not in EIM_SUPPORTED_PROTOCOL_BITS]
        if unknown:
            raise LocalEimError(f"Unknown eimSupportedProtocol bit(s) {', '.join(unknown)}; "
                                f"known: {', '.join(EIM_SUPPORTED_PROTOCOL_BITS)}.")
        configuration = EimConfigurationData(
            eim_id=eim_id, eim_fqdn=fqdn or None, eim_id_type=id_type, counter_value=counter, association_token=-1,
            eim_public_key_data=sign_key, trusted_public_key_data_tls=tls_key, eim_supported_protocol=protocols,
            euicc_ci_pk_id=ci_pkid, indirect_profile_download=indirect,
        )
        if len(fqdn) > 0 and not tls_setup.reserved_test_name(fqdn):
            self.emit(f"[!] eimFqdn {fqdn} is a live name: the card polls that host from now on, with the token it "
                      "assigns here; that eIM has to take the new token.")
        eid = self._card_eid()
        self.emit(f"[*] HANDOVER: eimId {eim_id} ({EIM_ID_TYPE_NAMES.get(id_type, id_type)}), eimFqdn {fqdn or '-'}, "
                  f"counterValue {counter}, eimPublicKeyData {sign} as {sign_form}, trustedPublicKeyDataTls "
                  f"{(tls_name + ' as ' + tls_form) if tls_key is not None else 'none'}, euiccCiPKId "
                  f"{ci_pkid.hex().upper() if ci_pkid else 'none'}, indirectProfileDownload {'on' if indirect else 'off'}, "
                  f"eimSupportedProtocol {', '.join(protocols)}")
        self.emit(f"[!] Warning: The Local eIM holds no private key for {sign}: after this the card refuses every package from "
                  "this rig (euiccPackageErrorUnsigned, SGP.32 v1.3 §5.9.1) until ASSOCIATE puts the identity back.")
        if not self._confirm_reset(flags, eid, f"hands the card to {eim_id} with AddInitialEim"):
            self.emit("[*] Not handed over.")
            return
        how = {"sign": sign, "sign_form": sign_form, "tls": tls_name or "none", "tls_form": tls_form}
        lines = self._with_reader("ASSOCIATE HANDOVER", lambda: self.engine.hand_over(
            self._exchange, eid, configuration, reset_first="--no-reset" not in flags, how=how,
        ))
        for line in lines:
            self.emit(f"[+] {line}")

    def cmd_tls_setup(self, argument: str = "") -> None:
        positional, pairs, flags = _split(argument)
        action = positional[0].lower() if positional else "list"
        directory = self.engine.directory
        if action == "list":
            active = tls_setup.active_name(directory)
            self.emit(f"[*] TLS setup in use: {active or 'identity (its own TLS certificate)'}")
            for setup in tls_setup.list_setups(directory):
                marker = "*" if setup.name == active else " "
                self.emit(f"  {marker} {setup.name:<24} FQDN {setup.effective_fqdn or '-'}, chain {setup.chain}, "
                          f"trust {setup.trust}, curve {setup.curve}, send {setup.send}, TLS {setup.versions}, "
                          f"leaf {setup.validity}" + (", shaped" if setup.layout or setup.ca_layout else "")
                          + (f", client auth {setup.client_auth}" if setup.client_auth != "none" else "")
                          + (", SNI required" if setup.sni == "required" else "")
                          + (f", leaf {setup.leaf}" if setup.leaf else ""))
            return
        if action == "results":
            self._tls_results(positional[1] if len(positional) > 1 else "", pairs, flags)
            return
        if action == "text":
            if len(positional) < 2:
                raise LocalEimError("Usage: " + DOCS["TLS-SETUP"]["usage"])
            self._emit_certificate_text(f"Certificate {positional[1]} as text", tls_setup.reference_text(positional[1]),
                                        pairs, flags)
            return
        if action == "leaf":
            self._tls_leaf(positional[1:], pairs, flags)
            return
        if len(positional) < 2:
            raise LocalEimError("Usage: " + DOCS["TLS-SETUP"]["usage"])
        name = positional[1]
        if action == "new":
            if "--replace" in flags:
                self._check_setup_is_free(name, flags, "rebuilds it")
            built = tls_setup.build_setup(directory, self.engine.identity(), tls_setup.parse_options(name, pairs),
                                          replace="--replace" in flags)
            self.emit(f"[+] TLS setup {built.name} built.")
            for line in tls_setup.describe_setup(directory, built):
                self.emit(f"    {line}")
            if "--use" in flags or "--apply" in flags:
                self._use_tls_setup(name, associate="--apply" in flags, confirmed="--yes" in flags)
            else:
                self._ensure_setup_served(name)
            return
        if action == "show":
            setup = tls_setup.load_setup(directory, name)
            in_use = " (in use)" if tls_setup.active_name(directory) == name else ""
            self.emit(f"[*] TLS setup {name}{in_use}")
            for line in tls_setup.describe_setup(directory, setup):
                self.emit(f"    {line}")
            return
        if action == "use":
            self._use_tls_setup(name, associate="--associate" in flags or "--apply" in flags,
                                confirmed="--yes" in flags)
            return
        if action == "remove":
            self._check_setup_is_free(name, flags, "removes it")
            tls_setup.remove_setup(directory, name)
            self.emit(f"[+] TLS setup {name} removed.")
            return
        if action == "client-cert":
            certificate_path, key_path = tls_setup.issue_client_certificate(directory, name, common_name=pairs.get("cn", ""))
            self.emit(f"[+] TLS setup {name}: client certificate {certificate_path} with key {key_path} "
                      "(a client that presents it passes the setup's client authentication).")
            return
        raise LocalEimError("Usage: " + DOCS["TLS-SETUP"]["usage"])

    def _check_setup_is_free(self, name: str, flags: dict[str, str], what: str) -> None:
        """Refuse to rebuild or remove a setup that further leaves or cards depend on, unless --force is given.

        Both replace the setup's CA: the leaves issued under it go with it, and
        a card associated under the setup trusts a CA that no longer signs
        anything until ASSOCIATE runs again.
        """
        if "--force" in flags:
            return
        try:
            issued = [variant.name for variant in tls_setup.list_leaves(self.engine.directory, name)][1:]
        except tls_setup.TlsSetupError:
            return
        cards = [record.eid for record in self.engine.records() if record.data.get("tls_setup") == name]
        if not issued and not cards:
            return
        holds: list[str] = []
        if issued:
            holds.append(f"{len(issued)} further leaf(s) ({', '.join(issued)})")
        if cards:
            holds.append(f"{len(cards)} card(s) associated under it ({', '.join(eid[-8:] for eid in cards)})")
        raise LocalEimError(f"TLS setup {name} has {' and '.join(holds)}; --force {what} anyway. Its CA goes with it: "
                            "the leaves are lost, and those cards need ASSOCIATE again.")

    def _tls_leaf(self, rest: list[str], pairs: dict[str, str], flags: dict[str, str]) -> None:
        """TLS-SETUP LEAF <setup> [LIST] | NEW <leaf> [options] | SHOW <leaf> | USE <leaf> | REMOVE <leaf>."""
        if len(rest) == 0:
            raise LocalEimError("Usage: " + DOCS["TLS-SETUP"]["usage"])
        directory = self.engine.directory
        setup_name = rest[0]
        action = rest[1].lower() if len(rest) > 1 else "list"
        setup = tls_setup.load_setup(directory, setup_name)
        if action == "list":
            on_the_name = tls_setup.served_leaf(setup)
            self.emit(f"[*] Leaves of TLS setup {setup_name} ({setup.effective_fqdn or '-'}); the card is told to trust "
                      f"{setup.trust}. * is on the name:")
            for variant in tls_setup.list_leaves(directory, setup_name):
                marker = "*" if variant.name == on_the_name else " "
                self.emit(f"  {marker} {variant.name:<24} {variant.sha256[:8]}  {tls_setup.leaf_summary(variant)}"
                          + (", shaped" if variant.layout else ""))
            return
        if len(rest) < 3:
            raise LocalEimError("Usage: " + DOCS["TLS-SETUP"]["usage"])
        leaf_name = rest[2]
        if action == "new":
            written = self._leaf_text_given(pairs)
            options = tls_setup.parse_leaf_options(setup, leaf_name, pairs, spec=written)
            if "--use" in flags:
                # Asked before anything is issued, so a refusal leaves no leaf behind to trip a second try.
                self._check_leaf_swap(setup, leaf_name, flags)
            variant = tls_setup.issue_leaf(directory, self.engine.identity(), setup_name, options,
                                           replace="--replace" in flags)
            self.emit(f"[+] Leaf {variant.name} issued under TLS setup {setup_name}.")
            for line in tls_setup.describe_leaf(directory, setup_name, variant):
                self.emit(f"    {line}")
            if "--use" in flags:
                self._use_tls_leaf(setup_name, leaf_name, flags)
            else:
                self.emit(f"[*] The listener still serves {tls_setup.served_leaf(setup)}; TLS-SETUP LEAF {setup_name} USE "
                          f"{leaf_name} puts this one on the name.")
            return
        if action == "show":
            variant = tls_setup.load_leaf(directory, setup_name, leaf_name)
            self.emit(f"[*] Leaf {leaf_name} of TLS setup {setup_name}")
            for line in tls_setup.describe_leaf(directory, setup_name, variant):
                self.emit(f"    {line}")
            if "--der" in flags:
                # What an UPDATE-EIM operation takes as tls_certificate=, for either trust form.
                certificate, public_key = tls_setup.leaf_der(directory, setup_name, leaf_name)
                self.emit(f"    certificate DER {certificate.hex().upper()}")
                self.emit(f"    public key DER (SubjectPublicKeyInfo) {public_key.hex().upper()}")
            return
        if action == "text":
            self._emit_certificate_text(f"Leaf {leaf_name} of TLS setup {setup_name} as text",
                                        tls_setup.leaf_text(directory, setup_name, leaf_name), pairs, flags)
            return
        if action == "use":
            self._use_tls_leaf(setup_name, leaf_name, flags)
            return
        if action == "remove":
            tls_setup.remove_leaf(directory, setup_name, leaf_name)
            self.emit(f"[+] Leaf {leaf_name} of TLS setup {setup_name} removed.")
            return
        raise LocalEimError("Usage: " + DOCS["TLS-SETUP"]["usage"])

    @staticmethod
    def _leaf_text_given(pairs: dict[str, str]) -> str:
        """The certificate text a LEAF NEW line carries; its keys leave *pairs*, the leaf options stay.

        ``text=<file>`` reads the whole text; otherwise ``subject=``, each
        ``ext.<extension>=`` in the order given and ``extensions=none`` make
        its lines. A file is opened here only: a shell line names it, no
        request does. ``lines=`` carries the text itself, for a caller that
        already holds it (the GUI action).
        """
        inline = pairs.pop("lines", None)
        if inline is not None:
            if any(key in pairs for key in ("text", "subject", "extensions")) or any(key.startswith("ext.") for key in pairs):
                raise LocalEimError("lines= carries the whole certificate text; leave text=, subject=, "
                                    "ext.<extension>= and extensions= out.")
            return inline
        source = pairs.pop("text", None)
        subject = pairs.pop("subject", None)
        none = pairs.pop("extensions", None)
        named = [(key[len("ext."):], pairs.pop(key)) for key in [key for key in pairs if key.startswith("ext.")]]
        if source is not None:
            if subject is not None or none is not None or named:
                raise LocalEimError("text=<file> carries the subject and the extensions; leave subject=, "
                                    "ext.<extension>= and extensions= out.")
            path = Path(source).expanduser()
            try:
                if path.stat().st_size > _CERTIFICATE_TEXT_MAX:
                    raise LocalEimError(f"{path} is larger than a certificate text ({_CERTIFICATE_TEXT_MAX} octets).")
                written = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                raise LocalEimError(f"text= names a file with the certificate text; {path} does not read: {error}") from error
            # A refusal of a text quotes what it could not read. A file that is no certificate text is
            # turned away here, by line number alone, so that naming some other file shows none of it.
            for number, raw in enumerate(written.splitlines(), start=1):
                key = raw.partition("=")[0].strip()
                if len(raw.strip()) == 0 or raw.strip().startswith("#"):
                    continue
                if "=" not in raw or not cert_spec.is_key(key):
                    raise LocalEimError(f"{path} is not a certificate text: line {number} is no subject, rdn or "
                                        "extension line.")
            return written
        lines: list[str] = []
        if subject is not None:
            lines.append(f"subject = {subject}")
        if none is not None:
            lines.append(f"extensions = {none}")
        lines.extend(f"{name} = {value}" for name, value in named)
        return "\n".join(lines)

    def _emit_certificate_text(self, title: str, text: str, pairs: dict[str, str], flags: dict[str, str]) -> None:
        """Print a certificate text, or write it to out=<file> for an editor and text=<file>."""
        target = pairs.get("out", "")
        if len(target) == 0:
            self.emit(f"[*] {title}:")
            for line in text.splitlines():
                self.emit(f"    {line}")
            return
        path = Path(target).expanduser()
        try:
            # Created, never written over: out= names a new file.
            with path.open("x", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except FileExistsError as error:
            raise LocalEimError(f"{path} exists; out= writes a new file and never over one.") from error
        except OSError as error:
            raise LocalEimError(f"{path} cannot be written: {error}") from error
        self.emit(f"[+] {title} written to {path} ({len(text.splitlines())} lines).")

    @staticmethod
    def _check_leaf_swap(setup: tls_setup.TlsSetup, leaf_name: str, flags: dict[str, str]) -> None:
        """Refuse to put another leaf on the name of a setup that pins the leaf, unless the caller said how.

        A card associated under such a setup trusts the leaf itself, so it
        refuses the next one until a write tells it; a swap that says nothing
        about the card would look like a card that dislikes the certificate.
        """
        if not tls_setup.trust_follows_leaf(setup) or tls_setup.served_leaf(setup) == leaf_name:
            return
        if "--associate" in flags or "--serve-only" in flags:
            return
        raise LocalEimError(
            f"TLS setup {setup.name} tells the card to trust the leaf itself (trust={setup.trust}), so a card "
            "associated under it refuses another leaf until it is told. Say which: --associate serves the leaf and "
            "re-runs ASSOCIATE (the card's eIM configuration is reset); --serve-only serves it and leaves the card "
            "as it is. Without a reset, an UPDATE-EIM operation delivered before the swap tells the card: its "
            f"tls_certificate= takes the hex TLS-SETUP LEAF {setup.name} SHOW {leaf_name} --der prints (the "
            f"{'public key' if setup.trust == 'leaf_key' else 'certificate'} for this setup).")

    def _use_tls_leaf(self, setup_name: str, leaf_name: str, flags: dict[str, str]) -> None:
        """Put a leaf on its setup's name and restart the listener; a setup that pins the leaf needs the card told."""
        directory = self.engine.directory
        setup = tls_setup.load_setup(directory, setup_name)
        variant = tls_setup.load_leaf(directory, setup_name, leaf_name)
        pinned = tls_setup.trust_follows_leaf(setup)
        changing = tls_setup.served_leaf(setup) != leaf_name
        self._check_leaf_swap(setup, leaf_name, flags)
        previous = tls_setup.use_leaf(directory, setup_name, leaf_name)
        if not changing:
            self.emit(f"[*] TLS setup {setup_name} already has leaf {leaf_name} on its name.")
        else:
            self.emit(f"[+] TLS setup {setup_name} serves leaf {leaf_name} ({variant.sha256[:8]}) on "
                      f"{setup.effective_fqdn or '-'}; before: {previous}.")
            status = restart_background()
            if status is None:
                self.emit("[*] The service is not running; SERVE start serves it.")
            elif status.get("tls_url"):
                self.emit(f"[+] Service restarted: card-facing TLS at {status['tls_url']}.")
            else:
                self.emit(f"[!] Service restarted without a card-facing TLS listener: {status.get('tls_note', '?')}")
        if "--associate" in flags:
            self.cmd_associate(f"setup={shlex.quote(setup_name)}" + (" --yes" if "--yes" in flags else ""))
        elif pinned and changing:
            self.emit("[!] Warning: The card still trusts the leaf it was given and refuses this one until it is told.")
        elif changing:
            self.emit(f"[*] A card that trusts this setup's {setup.trust} meets the leaf at its next connection; "
                      f"TLS-SETUP RESULTS {setup_name} shows what it did.")

    def _tls_results(self, setup_name: str, pairs: dict[str, str], flags: dict[str, str]) -> None:
        """TLS-SETUP RESULTS [<setup>] [n=<rows>] [--rows] [--json]: the recorded handshakes per leaf served."""
        directory = self.engine.directory
        try:
            count = max(1, int(pairs.get("n", "40")))
        except ValueError as error:
            raise LocalEimError(f"TLS-SETUP RESULTS takes a number for n=: {error}") from error
        results = tls_results.leaf_results(self.engine.store, directory, setup_name)
        rows = self.engine.store.handshakes(limit=count, setup=setup_name, newest_first=True)
        rows.reverse()
        if "--json" in flags:
            self.emit(json.dumps({"results": [result.as_dict() for result in results],
                                  "handshakes": [vars(row) for row in rows] if "--rows" in flags else []},
                                 indent=2, default=str))
            return
        seen = sum(result.attempts for result in results)
        self.emit(f"[*] TLS results{' for ' + setup_name if setup_name else ''}: {seen} handshake(s) on record. Only a "
                  "full handshake says something about a leaf; a resumed session checks no certificate.")
        for line in tls_results.result_lines(results):
            self.emit(line)
        if "--rows" in flags:
            self.emit(f"[*] The newest {len(rows)} handshake(s), oldest first:")
            for row in rows:
                self.emit("    " + tls_results.handshake_line(row))

    def _use_tls_setup(self, name: str, *, associate: bool, confirmed: bool, hint: bool = True) -> None:
        try:
            tls_setup.use_setup(self.engine.directory, name)
        except tls_setup.TlsSetupError as error:
            raise LocalEimError(str(error)) from error
        label = "the identity's own TLS certificate" if name in ("", "identity") else f"TLS setup {name}"
        self.emit(f"[+] The card-facing listener serves {label}.")
        status = restart_background()
        if status is None:
            self.emit("[*] The service is not running; SERVE start serves it.")
        elif status.get("tls_url"):
            self.emit(f"[+] Service restarted: card-facing TLS at {status['tls_url']} for {status.get('eim_fqdn') or '-'}.")
        else:
            self.emit(f"[!] Service restarted without a card-facing TLS listener: {status.get('tls_note', '?')}")
        if associate:
            # USE <name> --associate means that setup, whatever the card remembers.
            self.cmd_associate(f"setup={shlex.quote(name or 'identity')}" + (" --yes" if confirmed else ""))
        elif hint:
            self.emit("[*] The card trusts what its last AddInitialEim carried; ASSOCIATE sends the new trust and name.")

    def cmd_serve(self, argument: str = "") -> None:
        positional, pairs, flags = _split(argument)
        action = positional[0].lower() if positional else "status"
        if action == "start":
            status = start_background(host=pairs.get("host", "127.0.0.1"), port=int(pairs.get("port", DEFAULT_PORT)),
                                      tls="--tls" in flags, tls_port=pairs.get("tls_port", "auto"),
                                      smdp_tls_port=pairs.get("smdp_tls_port", "auto"),
                                      smds_tls_port=pairs.get("smds_tls_port", "auto"))
            self.emit(f"[+] Local eIM service running at {status['url']} (pid {status['pid']}).")
            self.emit(f"    eIM FQDN {status.get('eim_fqdn') or '-'}, SM-DP+ {status.get('smdp_address') or '-'} "
                      f"and SM-DS {status.get('smds_address') or '-'} now route to it from the eSIM Management "
                      "console and any IPA polling the eIM FQDN.")
            self._emit_card_listener(status)
            return
        if action == "restart":
            status = restart_background()
            if status is None:
                self.emit("[*] Not running. SERVE start launches it.")
                return
            self.emit(f"[+] Restarted at {status['url']} (pid {status['pid']}).")
            self._emit_card_listener(status)
            return
        if action == "stop":
            self.emit("[+] Stopped." if stop_background() else "[*] Not running.")
            return
        status = describe()
        if not status.get("running"):
            self.emit(f"[*] Not running. SERVE start launches it (log: {status['log']}).")
            return
        self.emit(f"[*] Running at {status['url']} (pid {status['pid']}, since {status.get('started_at', '?')}), "
                  f"answering: {'yes' if status.get('answers') else 'no'}")
        self.emit(f"    eIM {status.get('eim_id') or '-'} / {status.get('eim_fqdn') or '-'}; "
                  f"SM-DP+ {status.get('smdp_address') or '-'}; SM-DS {status.get('smds_address') or '-'}; "
                  f"log {status['log']}")
        self._emit_card_listener(status)

    def _emit_card_listener(self, status: dict[str, Any]) -> None:
        if status.get("tls_url"):
            self.emit(f"    card-facing TLS {status['tls_url']} serving {status.get('tls_setup') or '-'} "
                      f"(TLS {status.get('tls_versions') or '-'}): a card's IPAe that resolves "
                      f"{status.get('eim_fqdn') or 'the eIM FQDN'} through the terminal driving it lands here.")
        else:
            self.emit(f"    {status.get('tls_note') or 'no card-facing TLS listener'}")
        if status.get("tls_keylog"):
            self.emit(f"    TLS key log {status['tls_keylog']} (NSS key log format): Wireshark decrypts a capture "
                      "of the card-facing sessions with it.")
        if status.get("smdp_tls_url"):
            self.emit(f"    SM-DP+ card-facing TLS {status['smdp_tls_url']}, certificate "
                      f"{status.get('smdp_tls_material') or '-'}: a card's IPAe that downloads directly from "
                      f"{status.get('smdp_fqdn') or 'the SM-DP+ address'} lands here (ES9+, ASN.1 binding).")
        else:
            self.emit(f"    {status.get('smdp_tls_note') or 'no SM-DP+ card-facing TLS listener'}")
        if status.get("smds_tls_url"):
            self.emit(f"    SM-DS card-facing TLS {status['smds_tls_url']}, certificate "
                      f"{status.get('smds_tls_material') or '-'}: a card's IPAe that retrieves its Event Records "
                      f"from {status.get('smds_address') or 'the SM-DS address'} itself lands here (ES11, ASN.1 "
                      "binding).")
        else:
            self.emit(f"    {status.get('smds_tls_note') or 'no SM-DS card-facing TLS listener'}")

    def cmd_deliver(self, argument: str = "") -> None:
        _positional, _pairs, flags = _split(argument)
        steps = self._with_reader(
            "DELIVER",
            lambda: deliver(self.engine, self._exchange, once="--once" in flags, emit=self.emit,
                            reset=self._reset_card),
        )
        self.emit(f"[*] {len(steps)} package(s) delivered.")
        # After the reader is given back: a receiver that answers slowly must not hold the card.
        if not self.defer_notification_pass:
            self.forward_due_notifications()

    def _report_notifications(self, outcomes: list[outbox.Outcome]) -> None:
        for outcome in outcomes:
            mark = "[+]" if outcome.delivered else "[!]" if outcome.problem else "[*]"
            self.emit(f"{mark} {outcome.line()}")

    def forward_due_notifications(self) -> None:
        """Send on the Notifications that are due, the ones the run just handed over included."""
        self._report_notifications(self.engine.forward_notifications())

    def cmd_notifications(self, argument: str = "") -> None:
        """NOTIFICATIONS [<eid>] | NOTIFICATIONS SEND [<eid>] [<seqNumber> ...]."""
        positional, pairs, flags = _split(argument)
        action = positional[0].upper() if positional and positional[0].upper() == "SEND" else ""
        eid = ""
        numbers: list[int] = []
        for token in positional[1:] if action else positional:
            if _looks_like_eid(token) and not eid:
                eid = codec.normalize_eid(token)
            elif token.isdigit() and len(token) < 12:
                numbers.append(int(token))
            else:
                raise LocalEimError("Usage: " + DOCS["NOTIFICATIONS"]["usage"])
        if pairs or flags or (numbers and not action):
            raise LocalEimError("Usage: " + DOCS["NOTIFICATIONS"]["usage"])
        if eid and self.engine.record(eid) is None:
            raise LocalEimError(f"No eUICC {eid}. EUICC lists the records.")
        if numbers and not eid:
            raise LocalEimError("Name the eUICC: a seqNumber counts per eUICC.")
        if action == "SEND":
            outcomes = self.engine.forward_notifications(eid, seq_numbers=numbers, explicit=True)
            self._report_notifications(outcomes)
            if not outcomes:
                self.emit("[*] No Notification to send. A failed or kept one is sent when its seqNumber is named: "
                          "NOTIFICATIONS SEND <eid> <seqNumber>.")
            return
        rows = self.engine.notifications(eid)
        if not rows:
            self.emit("[*] No Notifications on record" + (f" for {eid}." if eid else "."))
        current = ""
        for row in rows:
            if row["eid"] != current:
                current = row["eid"]
                tally = outbox.counts(self.engine.record(current))
                summary = ", ".join(f"{count} {state}" for state, count in tally.items() if count)
                self.emit(f"[*] {current}: {summary}")
            self.emit(f"    {row['text']}")
        if rows:
            self.emit("[*] A pending Notification goes to its receiver after DELIVER and INJECT and while the service "
                      "runs; a failed or kept one goes only by NOTIFICATIONS SEND <eid> <seqNumber>.")

    def _inject_eid(self, named: str) -> str:
        """The eUICC an INJECT is for: the one named, else the one record that has an inject target."""
        if named:
            eid = codec.normalize_eid(named)
            if self.engine.record(eid) is None:
                raise LocalEimError(f"No eUICC {eid}. EUICC lists the records.")
            return eid
        with_target = [record.eid for record in self.engine.records() if self.engine.inject_target(record.eid)]
        if len(with_target) == 1:
            return with_target[0]
        if not with_target:
            raise LocalEimError("No eUICC has an inject target. Name one: INJECT <eid> target=http://127.0.0.1:<port> "
                                "(EIM-LISTEN in the eSIM Management console prints the line).")
        raise LocalEimError("More than one eUICC has an inject target; name one: " + ", ".join(with_target))

    def cmd_inject(self, argument: str = "") -> None:
        """INJECT [<eid>] [target=<url>|none] [binding=asn1|json] [timeout=<seconds>] [--once]."""
        positional, pairs, flags = _split(argument)
        if len(positional) > 1 or set(pairs) - {"target", "binding", "timeout"} or set(flags) - {"--once"}:
            raise LocalEimError("Usage: " + DOCS["INJECT"]["usage"])
        try:
            timeout = float(pairs["timeout"]) if pairs.get("timeout") else DEFAULT_TIMEOUT_S
        except ValueError as error:
            raise LocalEimError(f"timeout takes seconds: {error}") from error
        if not timeout > 0:
            raise LocalEimError("timeout takes seconds above 0.")
        eid = self._inject_eid(positional[0] if positional else "")
        stored = self.engine.inject_target(eid) or {}
        if "target" in pairs and pairs["target"].strip().lower() in ("", "none"):
            self.engine.set_inject_target(eid, "")
            self.emit(f"[+] {eid}: inject target cleared.")
            return
        url = pairs.get("target", stored.get("url", ""))
        if url and ("target" in pairs or "binding" in pairs):
            self.engine.set_inject_target(eid, url, pairs.get("binding", stored.get("binding", "asn1")))
            stored = self.engine.inject_target(eid) or {}
        if not stored:
            raise LocalEimError(f"No inject target for {eid}. Give target=http://127.0.0.1:<port>: the address "
                                "EIM-LISTEN prints in the eSIM Management console.")
        target = parse_target(stored["url"], stored["binding"])
        log = TrafficLog(self.engine, target, eid)
        transport = transport_for(self.engine, target, timeout=timeout, record=log)
        carried = "HTTPS with the eIM's client certificate" if target.secure else "plain HTTP on the loopback"
        self.emit(f"[*] {eid}: injecting to {target.url} ({target.binding} binding, {carried}).")
        try:
            steps = inject(self.engine, eid, transport, once="--once" in flags, emit=self.emit, on_serve=log.serving)
        except TargetUnreachable as error:
            self.emit(f"[!] {error}. Nothing was served; is EIM-LISTEN running there?")
            return
        self.emit(f"[*] {len(steps)} package(s) injected.")
        self.forward_due_notifications()

    def cmd_inject_cert(self, argument: str = "") -> None:
        """INJECT-CERT: the client certificate this eIM presents to an IPA over HTTPS, made on first use."""
        from SCP11.shared import tls_identity

        if argument.strip():
            raise LocalEimError("Usage: " + DOCS["INJECT-CERT"]["usage"])
        made = self.engine.inject_client_pair() is None
        certificate, key = self.engine.make_inject_client_pair()
        self.emit(f"[+] The eIM's client certificate for injection{' (made now)' if made else ''}: {certificate}")
        self.emit(f"    {tls_identity.describe(certificate)}")
        self.emit(f"    its private key (mode 0600): {key}")
        self.emit(f"[*] On the IPA: EIM-LISTEN host=<address> cert=<pem> key=<pem> client-ca={certificate}")

    def cmd_settings(self, argument: str = "") -> None:
        _positional, pairs, _flags = _split(argument)
        for key, value in pairs.items():
            self.engine.set_setting(key, value)
        for key, value in self.engine.settings().items():
            self.emit(f"    {key:<24} {value}")
        if "tls_keylog" in pairs:
            self.emit("    tls_keylog is read when the service starts: SERVE restart applies it; the file is "
                      "tls-keylog.txt in the store directory (NSS key log format, for Wireshark).")

    def cmd_package_import(self, argument: str = "") -> None:
        """PACKAGE-IMPORT <file|folder> [eid] [--plan]."""
        import os

        from SCP11.eim_local.eim_package_codec import load_eim_package_document
        from SCP11.eim_local.engine.package_import import requests_from_document

        positional, _pairs, flags = _split(argument)
        if not positional:
            raise LocalEimError("Usage: " + DOCS["PACKAGE-IMPORT"]["usage"])
        source = positional[0]
        eid = codec.normalize_eid(positional[1]) if len(positional) > 1 else self._unnamed_eid()
        session = self.shell.session
        if os.path.isdir(source):
            paths = session.list_eim_package_files(package_dir=source)
        else:
            paths = [source]
        default_smdp = ""
        try:
            default_smdp = str(session._effective_smdp_address() or "")
        except (AttributeError, OSError, ValueError):
            default_smdp = ""
        requests: list[OperationRequest] = []
        for path in paths:
            try:
                requests.extend(requests_from_document(load_eim_package_document(path), eid, default_smdp=default_smdp))
            except OperationError as error:
                self.emit(f"[!] {path}: {error}")
        if not requests:
            raise LocalEimError("Nothing to import.")
        if "--plan" in flags:
            for entry in self.engine.plan(requests):
                self.emit(f"[plan] {entry.type}: {entry.description}  ({entry.preview_hex or '-'})")
            return
        created = self.engine.submit(requests, author="eim-local shell", summary=f"import of {source}")
        self.emit(f"[+] Queued {len(created)} operation(s) from {len(paths)} document(s):")
        for operation in created:
            self._print_operation_line(operation)

    def cmd_smdp_profile(self, argument: str = "") -> None:
        positional, _pairs, _flags = _split(argument)
        smdp = LocalSmdp(store_directory())
        if len(positional) >= 2:
            smdp.set_profile(positional[0], "" if positional[1] == "-" else positional[1])
        profiles = smdp.profiles()
        self.emit(f"[*] Local SM-DP+ {smdp.address() or '-'}: {len(profiles)} Matching ID(s); others get the "
                  "configured profile.")
        for key, value in sorted(profiles.items()):
            self.emit(f"    {key:<24} {value}")

    def cmd_smds(self, argument: str = "") -> None:
        """SMDS [status] | LIST [<eid>] | REGISTER <eid> [<eventId>] [rsp=] [type=] | DELETE <eid> <eventId> |
        ADDRESS [<fqdn>]. The store's own SM-DS; no verb opens a reader."""
        positional, pairs, _flags = _split(argument)
        action = positional[0].upper() if positional else "STATUS"
        smds = LocalSmds(store_directory(), store=self.engine.store)
        if action == "REGISTER":
            if len(positional) < 2:
                raise LocalEimError("SMDS REGISTER <eid> [<eventId>] [rsp=<address>] [type=download|rpm]")
            rsp = pairs.get("rsp", "") or LocalSmdp(store_directory()).address()
            kinds = {"download": EVENT_TYPE_PROFILE_DOWNLOAD, "rpm": EVENT_TYPE_RPM}
            kind = str(pairs.get("type", "download")).strip().lower()
            if kind not in kinds:
                raise LocalEimError("type is download or rpm.")
            event_id = positional[2] if len(positional) > 2 else pairs.get("event", "")
            made_up = len(event_id) == 0
            if made_up:
                import secrets

                event_id = secrets.token_hex(8).upper()
            event = smds.register_event(positional[1], rsp, event_id, event_type=kinds[kind])
            self.emit(f"[+] Event Record registered for {event.eid}: EventID {event.event_id} at "
                      f"{event.rsp_server_address} ({EVENT_TYPES[event.event_type]})"
                      + (", the EventID made up here." if made_up else "."))
            self.emit(f"    QUEUE DOWNLOAD {event.eid} contact_smds=on indirect=on smds_address={smds.address()} "
                      "has the eIM retrieve it; the EventID is the Matching ID of the download that follows.")
            return
        if action == "DELETE":
            if len(positional) < 3:
                raise LocalEimError("SMDS DELETE <eid> <eventId>")
            removed = smds.delete_event(positional[1], positional[2])
            self.emit(f"[+] {len(removed)} Event Record(s) deleted: EventID {positional[2]} of {removed[0].eid}.")
            return
        if action == "ADDRESS":
            if len(positional) < 2:
                self.emit(f"[*] Local SM-DS address: {smds.address() or '-'}")
                return
            wanted = str(positional[1]).strip().lower().rstrip(".")
            smdp = LocalSmdp(store_directory())
            if wanted in (str(smdp.address() or "").strip().lower().rstrip("."), smdp.host()):
                raise LocalEimError(f"{wanted} is the address of the local SM-DP+: one name cannot stand for both "
                                    "servers on the paths they share.")
            if local_eim_name(wanted):
                raise LocalEimError(f"{wanted} is a Local eIM name: the eIM's own listener serves it.")
            address = str(self.engine.set_setting(SETTING_SMDS_ADDRESS, positional[1]))
            self.emit(f"[+] The local SM-DS answers under {address}.")
            if describe().get("running"):
                # Other processes find the service by the names in its status file.
                restart_background()
                self.emit("    The running service was restarted, so every process finds it under that name.")
            return
        if action == "LIST":
            self._emit_smds_events(smds, positional[1] if len(positional) > 1 else "")
            return
        if action != "STATUS":
            raise LocalEimError("SMDS [status] | LIST [<eid>] | REGISTER <eid> [<eventId>] | DELETE <eid> <eventId> "
                                "| ADDRESS [<fqdn>]")
        events = smds.events()
        eids = {event.eid for event in events}
        self.emit(f"[*] Local SM-DS {smds.address() or '-'}: {len(events)} Event Record(s) for {len(eids)} eUICC(s).")
        smds.smdp = LocalSmdp(store_directory())
        if smds.taken_by_the_smdp():
            self.emit(f"[!] Warning: {smds.address()} is also the address of the local SM-DP+, which keeps the name: the SM-DS "
                      "answers nothing until SMDS ADDRESS gives it another.")
        try:
            credentials = smds.material().credentials
        except (OSError, ValueError, RuntimeError) as error:
            credentials = ()
            self.emit(f"    CERT.DSauth.SIG could not be loaded: {error}")
        if len(credentials) > 0:
            listed = ", ".join(f"{item.label or 'CERT.DSauth.SIG'} under eSIM CA {item.root_ci_pkid.hex().upper()[:8]}"
                               for item in credentials)
            self.emit(f"    SM-DS OID {smds.oid() or '-'}; {listed}.")
            self.emit("    Only an eUICC that trusts the SGP.26 test eSIM CA accepts this SM-DS.")
        else:
            self.emit("    No Variant O CERT.DSauth.SIG in the SGP.26 bundle: ES11.InitiateAuthentication is answered "
                      "SM-DS Certificate - Unavailable.")
        status = describe()
        if not status.get("running"):
            self.emit("    The service is not running: SERVE start, and an IPA reaches the eIM and this SM-DS through it.")
        elif str(status.get("smds_address") or "") != smds.address():
            self.emit(f"    The running service still answers under {status.get('smds_address') or 'no SM-DS name'}: "
                      "SERVE restart.")
        else:
            self.emit(f"    ES11 is answered at {status['url']}: the JSON binding on the ES9+ paths, the ASN.1 "
                      "binding on /gsma/rsp2/asn1.")
        self._emit_smds_events(smds, "", heading=False)

    def _emit_smds_events(self, smds: LocalSmds, eid: str, *, heading: bool = True) -> None:
        events = smds.events(eid)
        if heading:
            self.emit(f"[*] {len(events)} Event Record(s)" + (f" for {events[0].eid}" if eid and events else "")
                      + f" at the local SM-DS {smds.address() or '-'}.")
        for event in events:
            # Each row reads without its columns: the page shows a line as one box of running text.
            self.emit(f"    EventID {event.event_id} for {event.eid} at {event.rsp_server_address} "
                      f"({EVENT_TYPES.get(event.event_type, str(event.event_type))}), registered {event.at}")


def install_engine_verbs(shell: Any) -> EngineVerbs:
    verbs = EngineVerbs(shell)
    verbs.install()
    return verbs


__all__ = ["DOCS", "EngineVerbs", "FAULTS", "HELP_SECTIONS", "QUEUE_VERBS", "install_engine_verbs"]
