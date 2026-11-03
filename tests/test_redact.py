import unittest

from vpskitlib.util import redact_text


class RedactTest(unittest.TestCase):
    def test_json_keys(self):
        text = '{"privateKey": "A' + "b" * 42 + '", "id": "11111111-2222-3333-4444-555555555555", "shortIds": ["abc", "def"], "password": "secret-value"}'
        out = redact_text(text)
        self.assertNotIn("b" * 42, out)
        self.assertNotIn("11111111", out)
        self.assertNotIn("secret-value", out)
        self.assertNotIn("abc", out)
        self.assertIn('"privateKey": "***"', out)

    def test_plain_keys(self):
        out = redact_text("password=abc123 private_key: zzz")
        self.assertNotIn("abc123", out)
        self.assertNotIn("zzz", out)
        self.assertIn("password=***", out)


if __name__ == "__main__":
    unittest.main()
