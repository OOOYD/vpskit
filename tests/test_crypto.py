import unittest
from vpskitlib import crypto


class CryptoTest(unittest.TestCase):
    def test_rfc7748_vector(self):
        k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(
            crypto.x25519(k, u).hex(),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        )

    def test_public_key(self):
        a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        self.assertEqual(
            crypto.public_from_private(a).hex(),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        )

    def test_base64_roundtrip(self):
        raw = bytes(range(32))
        text = crypto.b64u_encode(raw)
        self.assertNotIn("=", text)
        self.assertEqual(crypto.b64u_decode(text), raw)

    def test_keypair(self):
        priv, pub = crypto.generate_keypair()
        self.assertEqual(len(crypto.b64u_decode(priv)), 32)
        self.assertEqual(len(crypto.b64u_decode(pub)), 32)
        self.assertEqual(crypto.keypair_from_private(priv), (priv, pub))


if __name__ == "__main__":
    unittest.main()
