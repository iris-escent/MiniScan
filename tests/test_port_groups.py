import unittest

from port_groups import PORT_GROUP_SPECS, parse_ports


class ParsePortsTests(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_multiple_ports_are_sorted(self):
        self.assertEqual(parse_ports("443,22,80"), [22, 80, 443])

    def test_port_range_is_inclusive(self):
        self.assertEqual(parse_ports("8000-8003"), [8000, 8001, 8002, 8003])

    def test_duplicate_ports_are_removed(self):
        self.assertEqual(parse_ports("80,80,79-81"), [79, 80, 81])

    def test_whitespace_is_ignored(self):
        self.assertEqual(parse_ports(" 22, 80 , 443 "), [22, 80, 443])

    def test_every_named_group_can_be_expanded(self):
        for group in PORT_GROUP_SPECS:
            with self.subTest(group=group):
                ports = parse_ports(group)
                self.assertTrue(ports)
                self.assertGreaterEqual(ports[0], 1)
                self.assertLessEqual(ports[-1], 65535)

    def test_main_and_all_group_sizes(self):
        self.assertEqual(len(parse_ports("main")), 133)
        self.assertEqual(len(parse_ports("all")), 65535)

    def test_group_and_custom_ports_can_be_mixed(self):
        ports = parse_ports("db,22,8000-8002")

        self.assertIn(22, ports)
        self.assertIn(3306, ports)
        self.assertIn(8000, ports)
        self.assertEqual(ports, sorted(set(ports)))

    def test_port_must_be_in_valid_range(self):
        for value in ("0", "65536", "0-80", "65535-65536"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)

    def test_reversed_range_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "start port"):
            parse_ports("100-10")

    def test_unknown_group_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown port group"):
            parse_ports("unknown")

    def test_empty_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no ports"):
            parse_ports(" , ")


if __name__ == "__main__":
    unittest.main()
