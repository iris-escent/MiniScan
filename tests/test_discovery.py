import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

import discovery


def host_result(host, status, method="icmp", code=0, error=None):
    return {
        "host": host,
        "status": status,
        "method": method,
        "code": code,
        "error": error
    }


class PingHostTests(unittest.TestCase):
    @patch("discovery.subprocess.run")
    def test_ping_success(self, run):
        run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        result = discovery.ping_host("127.0.0.1", 0.2)

        self.assertEqual(result["status"], "alive")
        self.assertEqual(result["method"], "icmp")

    @patch("discovery.subprocess.run")
    def test_ping_no_response(self, run):
        run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="")

        result = discovery.ping_host("192.0.2.1", 0.2)

        self.assertEqual(result["status"], "no_response")
        self.assertIsNone(result["error"])

    @patch("discovery.subprocess.run", side_effect=FileNotFoundError)
    def test_missing_ping_command_is_reported(self, run):
        result = discovery.ping_host("127.0.0.1", 0.2)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "ping command not found")

    @patch("discovery.subprocess.run")
    def test_ping_process_timeout(self, run):
        run.side_effect = subprocess.TimeoutExpired("ping", 2)

        result = discovery.ping_host("192.0.2.1", 0.2)

        self.assertEqual(result["status"], "no_response")
        self.assertEqual(result["error"], "ping command timeout")


class TcpProbeTests(unittest.TestCase):
    @patch("discovery.scan_port")
    def test_open_probe_port_marks_host_alive_and_stops(self, scan_port):
        scan_port.side_effect = [
            {"status": "closed", "code": 111},
            {"status": "open", "code": 0},
        ]

        result = discovery.tcp_probe_host("10.0.0.1", 0.5)

        self.assertEqual(result["status"], "alive")
        self.assertEqual(result["method"], "tcp/443")
        self.assertEqual(scan_port.call_count, 2)
        self.assertEqual(
            scan_port.call_args_list,
            [call("10.0.0.1", 80, 0.5), call("10.0.0.1", 443, 0.5)]
        )

    @patch("discovery.scan_port")
    def test_closed_probe_ports_are_not_assets(self, scan_port):
        scan_port.return_value = {"status": "closed", "code": 111}

        result = discovery.tcp_probe_host("10.0.0.1", 0.5)

        self.assertEqual(result["status"], "no_response")
        self.assertEqual(scan_port.call_count, len(discovery.TCP_PROBE_PORTS))


class CheckHostAliveTests(unittest.TestCase):
    @patch("discovery.tcp_probe_host")
    @patch("discovery.ping_host")
    def test_icmp_success_skips_tcp_probe(self, ping_host, tcp_probe):
        ping_host.return_value = host_result("10.0.0.1", "alive")

        result = discovery.check_host_alive("10.0.0.1", 0.5)

        self.assertEqual(result["method"], "icmp")
        tcp_probe.assert_not_called()

    @patch("discovery.tcp_probe_host")
    @patch("discovery.ping_host")
    def test_tcp_probe_is_used_after_icmp_failure(self, ping_host, tcp_probe):
        ping_host.return_value = host_result("10.0.0.1", "no_response", code=1)
        tcp_probe.return_value = host_result("10.0.0.1", "alive", "tcp/80")

        result = discovery.check_host_alive("10.0.0.1", 0.5)

        self.assertEqual(result["status"], "alive")
        self.assertEqual(result["method"], "tcp/80")

    @patch("discovery.tcp_probe_host")
    @patch("discovery.ping_host")
    def test_both_methods_failing_returns_no_response(self, ping_host, tcp_probe):
        ping_host.return_value = host_result("10.0.0.1", "no_response", code=1)
        tcp_probe.return_value = host_result("10.0.0.1", "no_response", "tcp", 11)

        result = discovery.check_host_alive("10.0.0.1", 0.5)

        self.assertEqual(result["status"], "no_response")
        self.assertEqual(result["method"], "icmp+tcp")


class DiscoverHostsTests(unittest.TestCase):
    @patch("discovery.check_host_alive")
    def test_results_are_sorted_by_ip(self, check):
        check.side_effect = lambda host, timeout: host_result(host, "alive")

        results = discovery.discover_hosts(
            ["10.0.0.10", "10.0.0.2", "10.0.0.1"],
            3,
            0.5
        )

        self.assertEqual(
            [result["host"] for result in results],
            ["10.0.0.1", "10.0.0.2", "10.0.0.10"]
        )
        self.assertEqual(check.call_count, 3)

    def test_empty_host_list(self):
        self.assertEqual(discovery.discover_hosts([], 10, 0.5), [])

    @patch("discovery.check_host_alive")
    def test_one_discovery_exception_does_not_abort_other_hosts(self, check):
        def fake_check(host, timeout):
            if host == "10.0.0.2":
                raise RuntimeError("unexpected failure")
            return host_result(host, "alive")

        check.side_effect = fake_check

        results = discovery.discover_hosts(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            3,
            0.5
        )

        self.assertEqual(len(results), 3)
        self.assertEqual(results[1]["host"], "10.0.0.2")
        self.assertEqual(results[1]["status"], "error")


if __name__ == "__main__":
    unittest.main()
