import unittest
from unittest.mock import patch

import server
from probes import parse_http_response, probe_redis, sanitize_banner


class HttpResponseTests(unittest.TestCase):
    def test_status_server_and_title_are_parsed(self):
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Server: TestServer/1.0\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<html><title> Test &amp; Scan </title></html>"
        )

        result = parse_http_response(response)

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["server"], "TestServer/1.0")
        self.assertEqual(result["title"], "Test & Scan")

    def test_non_http_response_is_rejected(self):
        self.assertIsNone(parse_http_response("SSH-2.0-OpenSSH"))

    def test_optional_headers_and_title_can_be_missing(self):
        result = parse_http_response("HTTP/1.0 204 No Content\r\n\r\n")

        self.assertEqual(result["status_code"], 204)
        self.assertIsNone(result["server"])
        self.assertIsNone(result["title"])

    def test_malformed_http_status_is_rejected(self):
        for response in ("HTTP/1.1", "HTTP/1.1 ABC Invalid\r\n\r\n"):
            with self.subTest(response=response):
                self.assertIsNone(parse_http_response(response))


class BannerFormattingTests(unittest.TestCase):
    def test_control_characters_are_escaped_on_one_line(self):
        banner = "MySQL\x00\n\x1b[31m"

        self.assertEqual(
            sanitize_banner(banner),
            r"MySQL\x00\n\x1b[31m"
        )

    def test_long_banners_are_truncated(self):
        self.assertEqual(sanitize_banner("abcdef", 3), "abc...")


class RedisProbeTests(unittest.TestCase):
    @patch("probes.socket.socket")
    def test_ping_pong_identifies_redis(self, socket_factory):
        sock = socket_factory.return_value
        sock.recv.return_value = b"+PONG\r\n"

        result = probe_redis("127.0.0.1", 6379, 0.5)

        self.assertEqual(result, "+PONG")
        sock.sendall.assert_called_once_with(b"PING\r\n")
        sock.close.assert_called_once()

    @patch("probes.socket.socket")
    def test_unrelated_response_is_rejected(self, socket_factory):
        socket_factory.return_value.recv.return_value = b"HTTP/1.1 200 OK\r\n"

        self.assertIsNone(probe_redis("127.0.0.1", 6379, 0.5))


class ServiceIdentificationTests(unittest.TestCase):
    def test_known_and_unknown_port_hints(self):
        self.assertEqual(server.identify_service(22), "ssh")
        self.assertEqual(server.identify_service(3306), "mysql")
        self.assertEqual(server.identify_service(65000), "unknown")

    def test_banner_signatures(self):
        cases = {
            "SSH-2.0-OpenSSH_9.0": "ssh",
            "220 FTP Server Ready": "ftp",
            "220 SMTP Ready": "smtp",
            "mysql_native_password": "mysql",
            "caching_sha2_password": "mysql",
            "+PONG redis": "redis",
        }
        for banner, expected in cases.items():
            with self.subTest(banner=banner):
                self.assertEqual(server.identify_banner_service(banner), expected)

    def test_probe_order_uses_port_hint(self):
        self.assertEqual(server.select_probes(8000), ["http", "https"])
        self.assertEqual(server.select_probes(8443), ["https", "http"])
        self.assertEqual(server.select_probes(6379), ["redis"])

    @patch("server.run_probe")
    @patch("server.grab_banner", return_value="SSH-2.0-Test")
    def test_recognized_banner_skips_active_probes(self, grab_banner, run_probe):
        result = server.detect_service("127.0.0.1", 2222, 0.5)

        self.assertEqual(result["service"], "ssh")
        self.assertEqual(result["banner"], "SSH-2.0-Test")
        run_probe.assert_not_called()

    @patch("server.grab_banner")
    @patch("server.run_probe")
    def test_redis_active_probe_runs_before_banner(self, run_probe, grab_banner):
        expected = {
            "service": "redis",
            "banner": "+PONG",
            "detail": {},
        }
        run_probe.return_value = expected

        result = server.detect_service("127.0.0.1", 6379, 0.5)

        self.assertEqual(result, expected)
        run_probe.assert_called_once_with("redis", "127.0.0.1", 6379, 0.5)
        grab_banner.assert_not_called()

    @patch("server.run_probe")
    @patch("server.grab_banner", return_value=None)
    def test_active_probe_result_is_returned(self, grab_banner, run_probe):
        expected = {
            "service": "http",
            "banner": None,
            "detail": {"status_code": 200}
        }
        run_probe.return_value = expected

        result = server.detect_service("127.0.0.1", 8000, 0.5)

        self.assertEqual(result, expected)
        self.assertEqual(run_probe.call_count, 1)

    @patch("server.run_probe", return_value=None)
    @patch("server.grab_banner", return_value=None)
    def test_failed_probes_keep_port_hint(self, grab_banner, run_probe):
        result = server.detect_service("127.0.0.1", 3306, 0.5)

        self.assertEqual(result["service"], "mysql")
        self.assertIsNone(result["banner"])


if __name__ == "__main__":
    unittest.main()
