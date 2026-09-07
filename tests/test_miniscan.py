import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import miniscan


class TargetParsingTests(unittest.TestCase):
    def test_single_host(self):
        self.assertEqual(miniscan.parse_hosts("127.0.0.1"), ["127.0.0.1"])

    def test_cidr_hosts(self):
        self.assertEqual(
            miniscan.parse_hosts("192.0.2.0/30"),
            ["192.0.2.1", "192.0.2.2"]
        )

    def test_invalid_host(self):
        with self.assertRaises(ValueError):
            miniscan.parse_hosts("not-an-ip")


class CommandLineTests(unittest.TestCase):
    def test_default_scan_options(self):
        args = miniscan.create_parser().parse_args(["-H", "127.0.0.1"])

        self.assertEqual(args.ports, "main")
        self.assertEqual(args.threads, 50)
        self.assertEqual(args.timeout, 1.0)
        self.assertFalse(args.no_ping)

    def test_invalid_runtime_options_exit_with_error(self):
        cases = [
            ["-H", "127.0.0.1", "-t", "0"],
            ["-H", "127.0.0.1", "--timeout", "0"],
            ["-H", "127.0.0.1", "-p", "invalid-group"],
        ]

        for args in cases:
            with self.subTest(args=args):
                with redirect_stdout(StringIO()), patch("sys.stderr", StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        miniscan.main(args)
                self.assertEqual(raised.exception.code, 2)


class HostResultTests(unittest.TestCase):
    def test_no_ping_results_only_treat_open_ports_as_assets(self):
        results = [
            {"host": "10.0.0.1", "port": 80, "status": "open", "code": 0},
            {"host": "10.0.0.2", "port": 80, "status": "closed", "code": 111},
        ]

        host_results = miniscan.host_results_from_open_ports(
            ["10.0.0.1", "10.0.0.2"],
            results
        )

        self.assertEqual(host_results[0]["status"], "alive")
        self.assertEqual(host_results[0]["method"], "tcp/80")
        self.assertEqual(host_results[1]["status"], "no_response")


class ReportTests(unittest.TestCase):
    def test_report_keeps_alive_hosts_and_open_ports(self):
        host_results = [
            {
                "host": "10.0.0.1", "status": "alive", "method": "icmp",
                "code": 0, "error": None
            },
            {
                "host": "10.0.0.2", "status": "no_response", "method": "icmp+tcp",
                "code": 1, "error": None
            },
        ]
        results = [
            {
                "host": "10.0.0.1", "port": 22, "status": "open", "code": 0,
                "service": "ssh", "banner": "SSH-2.0-Test", "detail": {}
            },
            {"host": "10.0.0.1", "port": 23, "status": "closed", "code": 111},
        ]

        report = miniscan.build_report(results, host_results, [22, 23], 10.0, 11.25)

        self.assertEqual(report["summary"]["total_hosts"], 2)
        self.assertEqual(report["summary"]["alive_hosts"], 1)
        self.assertEqual(report["summary"]["total_services"], 1)
        self.assertEqual(report["duration_seconds"], 1.25)
        self.assertEqual(len(report["hosts"]), 1)
        self.assertEqual(report["hosts"][0]["ports"][0]["service"], "ssh")

    @patch("miniscan.detect_service")
    @patch("miniscan.scan_ports")
    @patch("miniscan.discover_hosts")
    def test_no_ping_main_path_skips_discovery(
        self,
        discover_hosts,
        scan_ports,
        detect_service
    ):
        scan_ports.return_value = [
            {"host": "127.0.0.1", "port": 80, "status": "open", "code": 0}
        ]
        detect_service.return_value = {
            "service": "http",
            "banner": None,
            "detail": {"status_code": 200}
        }

        with redirect_stdout(StringIO()):
            report = miniscan.main([
                "-H", "127.0.0.1", "-p", "80", "--no-ping", "--open"
            ])

        discover_hosts.assert_not_called()
        self.assertEqual(report["summary"]["alive_hosts"], 1)
        self.assertEqual(report["summary"]["total_services"], 1)

    @patch("miniscan.detect_service")
    @patch("miniscan.scan_ports")
    @patch("miniscan.discover_hosts")
    def test_json_output_can_be_read_back(
        self,
        discover_hosts,
        scan_ports,
        detect_service
    ):
        discover_hosts.return_value = [
            {
                "host": "127.0.0.1", "status": "alive", "method": "icmp",
                "code": 0, "error": None
            }
        ]
        scan_ports.return_value = []

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "result.json"
            with redirect_stdout(StringIO()):
                miniscan.main([
                    "-H", "127.0.0.1", "-p", "80", "-o", str(output_path)
                ])

            data = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(data["summary"]["alive_hosts"], 1)
        self.assertEqual(data["hosts"][0]["host"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
