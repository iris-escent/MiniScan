import errno
import threading
import time
import unittest
from unittest.mock import patch

import scanner


class ScanPortTests(unittest.TestCase):
    @patch("scanner.socket.socket")
    def test_open_port(self, socket_factory):
        socket_factory.return_value.connect_ex.return_value = 0

        result = scanner.scan_port("127.0.0.1", 80, 0.5)

        self.assertEqual(result["status"], "open")
        self.assertEqual(result["code"], 0)
        socket_factory.return_value.close.assert_called_once()

    @patch("scanner.socket.socket")
    def test_closed_port(self, socket_factory):
        socket_factory.return_value.connect_ex.return_value = errno.ECONNREFUSED

        result = scanner.scan_port("127.0.0.1", 81, 0.5)

        self.assertEqual(result["status"], "closed")

    @patch("scanner.socket.socket")
    def test_timeout_port(self, socket_factory):
        socket_factory.return_value.connect_ex.return_value = errno.ETIMEDOUT

        result = scanner.scan_port("192.0.2.1", 80, 0.5)

        self.assertEqual(result["status"], "timeout")

    @patch("scanner.socket.socket")
    def test_other_socket_code_is_error(self, socket_factory):
        socket_factory.return_value.connect_ex.return_value = errno.EHOSTUNREACH

        result = scanner.scan_port("192.0.2.1", 80, 0.5)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], errno.EHOSTUNREACH)

    @patch("scanner.socket.socket")
    def test_socket_exception_is_returned_as_error(self, socket_factory):
        socket_factory.return_value.connect_ex.side_effect = OSError(
            errno.ENETUNREACH,
            "network unreachable"
        )

        result = scanner.scan_port("192.0.2.1", 80, 0.5)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], errno.ENETUNREACH)
        socket_factory.return_value.close.assert_called_once()


class ScanPortsTests(unittest.TestCase):
    def test_every_host_port_pair_is_scanned_once(self):
        calls = []
        submitted = []

        def fake_scan(host, port, timeout):
            calls.append((host, port, timeout))
            return {
                "host": host,
                "port": port,
                "status": "closed",
                "code": errno.ECONNREFUSED
            }

        with patch("scanner.scan_port", side_effect=fake_scan):
            results = scanner.scan_ports(
                ["10.0.0.1", "10.0.0.2"],
                [22, 80],
                2,
                0.5,
                on_submit=lambda host, port: submitted.append((host, port))
            )

        expected = {
            ("10.0.0.1", 22),
            ("10.0.0.1", 80),
            ("10.0.0.2", 22),
            ("10.0.0.2", 80),
        }
        self.assertEqual({(host, port) for host, port, _ in calls}, expected)
        self.assertEqual(set(submitted), expected)
        self.assertEqual(len(results), 4)

    def test_worker_limit_is_respected(self):
        lock = threading.Lock()
        active = 0
        maximum = 0

        def fake_scan(host, port, timeout):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.005)
            with lock:
                active -= 1
            return {"host": host, "port": port, "status": "closed", "code": 1}

        with patch("scanner.scan_port", side_effect=fake_scan):
            results = scanner.scan_ports(["127.0.0.1"], range(1, 31), 3, 0.5)

        self.assertEqual(len(results), 30)
        self.assertLessEqual(maximum, 3)

    def test_empty_targets_return_empty_results(self):
        self.assertEqual(scanner.scan_ports([], [80], 2, 0.5), [])
        self.assertEqual(scanner.scan_ports(["127.0.0.1"], [], 2, 0.5), [])

    def test_one_task_exception_does_not_abort_other_tasks(self):
        def fake_scan(host, port, timeout):
            if port == 80:
                raise RuntimeError("unexpected failure")
            return {"host": host, "port": port, "status": "open", "code": 0}

        with patch("scanner.scan_port", side_effect=fake_scan):
            results = scanner.scan_ports(
                ["127.0.0.1"],
                [22, 80, 443],
                2,
                0.5
            )

        by_port = {result["port"]: result for result in results}
        self.assertEqual(len(results), 3)
        self.assertEqual(by_port[22]["status"], "open")
        self.assertEqual(by_port[80]["status"], "error")
        self.assertEqual(by_port[443]["status"], "open")


if __name__ == "__main__":
    unittest.main()
