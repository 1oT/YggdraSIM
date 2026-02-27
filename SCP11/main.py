# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import sys
import argparse

try:
    from .config import SGPConfig
    from .console import SCP11Console
    from .factory import build_apdu_channel, build_profile_provider
    from .orchestrator import SGP22Orchestrator
except ImportError:
    from config import SGPConfig
    from console import SCP11Console
    from factory import build_apdu_channel, build_profile_provider
    from orchestrator import SGP22Orchestrator


class SGP22Client:
    """Compatibility wrapper preserving the previous main entrypoint."""

    def __init__(self):
        self.cfg = SGPConfig()
        self.apdu_channel = build_apdu_channel(self.cfg)
        self.profile_provider = build_profile_provider(self.cfg)
        self.orchestrator = SGP22Orchestrator(
            cfg=self.cfg,
            apdu_channel=self.apdu_channel,
            profile_provider=self.profile_provider,
        )

    def run_flow(self):
        try:
            self.orchestrator.run_flow()
        except Exception as error:
            print(f"\n[CRITICAL ERROR] {error}")
            sys.exit(1)

    def run_shell(self):
        console = SCP11Console(self)
        console.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SCP11 relay/local orchestration shell")
    parser.add_argument(
        "--flow",
        action="store_true",
        help="Run one-shot SCP11 flow instead of interactive shell",
    )
    args = parser.parse_args()

    client = SGP22Client()
    if args.flow:
        client.run_flow()
    else:
        client.run_shell()