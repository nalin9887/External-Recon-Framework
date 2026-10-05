import unittest

from reconfw.utils import expand_target, validate_target


class TargetValidationTests(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(validate_target("192.0.2.10"), "192.0.2.10")

    def test_ipv6(self):
        self.assertEqual(validate_target("2001:db8::1"), "2001:db8::1")

    def test_hostname(self):
        self.assertEqual(validate_target("WWW.Example.COM."), "www.example.com")

    def test_reject_option_injection(self):
        with self.assertRaises(ValueError):
            validate_target("-oN")

    def test_reject_url(self):
        with self.assertRaises(ValueError):
            validate_target("https://example.com")

    def test_cidr_expansion_cap(self):
        target = validate_target("192.0.2.0/30")
        self.assertEqual(expand_target(target, 4), ["192.0.2.1", "192.0.2.2"])

    def test_reject_large_cidr(self):
        target = validate_target("192.0.2.0/24")
        with self.assertRaises(ValueError):
            expand_target(target, 16)


if __name__ == "__main__":
    unittest.main()
