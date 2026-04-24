from __future__ import annotations

import unittest

from Tools.HilBridge import termshark_capture_pcap


class HilBridgeTermsharkCapturePcapTests(unittest.TestCase):
    def test_build_capture_command_forces_classic_pcap_output(self) -> None:
        command = termshark_capture_pcap.build_capture_command(
            ["-i", "lo", "-w", "/tmp/out.pcap", "-f", "udp port 4729"],
            capture_backend="/usr/bin/tshark",
        )

        self.assertEqual(
            command,
            [
                "/usr/bin/tshark",
                "-F",
                "pcap",
                "-i",
                "lo",
                "-w",
                "/tmp/out.pcap",
                "-f",
                "udp port 4729",
            ],
        )

    def test_build_capture_command_preserves_explicit_output_format(self) -> None:
        command = termshark_capture_pcap.build_capture_command(
            ["-F", "pcapng", "-i", "lo", "-w", "/tmp/out.pcapng"],
            capture_backend="/usr/bin/tshark",
        )

        self.assertEqual(
            command,
            [
                "/usr/bin/tshark",
                "-F",
                "pcapng",
                "-i",
                "lo",
                "-w",
                "/tmp/out.pcapng",
            ],
        )


if __name__ == "__main__":
    unittest.main()
