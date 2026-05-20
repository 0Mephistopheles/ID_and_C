import unittest
import tempfile
import os
from cryptography.hazmat.primitives.asymmetric import dsa

from Lab5.Lab5 import (
    generate_keys,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    sign_data,
    verify_signature
)


class TestDSSFunctions(unittest.TestCase):

    def setUp(self):
        self.private_key, self.public_key = generate_keys()
        self.data = b"Test message for DSS"

    def test_generate_keys(self):
        self.assertIsNotNone(self.private_key)
        self.assertIsNotNone(self.public_key)
        self.assertIsInstance(self.private_key, dsa.DSAPrivateKey)
        self.assertIsInstance(self.public_key, dsa.DSAPublicKey)

    def test_sign_data_returns_bytes(self):
        signature = sign_data(self.data, self.private_key)

        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 0)

    def test_verify_valid_signature(self):
        signature = sign_data(self.data, self.private_key)

        result = verify_signature(
            self.data,
            signature,
            self.public_key
        )

        self.assertTrue(result)

    def test_verify_invalid_signature_modified_data(self):
        signature = sign_data(self.data, self.private_key)

        modified_data = b"Modified message"

        result = verify_signature(
            modified_data,
            signature,
            self.public_key
        )

        self.assertFalse(result)

    def test_verify_invalid_signature_modified_signature(self):
        signature = bytearray(sign_data(self.data, self.private_key))

        signature[0] ^= 1

        result = verify_signature(
            self.data,
            bytes(signature),
            self.public_key
        )

        self.assertFalse(result)

    def test_save_and_load_private_key(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            path = tmp.name

        try:
            save_private_key(self.private_key, path)

            loaded_key = load_private_key(path)

            self.assertIsNotNone(loaded_key)
            self.assertIsInstance(loaded_key, dsa.DSAPrivateKey)

        finally:
            os.remove(path)

    def test_save_and_load_public_key(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            path = tmp.name

        try:
            save_public_key(self.public_key, path)

            loaded_key = load_public_key(path)

            self.assertIsNotNone(loaded_key)
            self.assertIsInstance(loaded_key, dsa.DSAPublicKey)

        finally:
            os.remove(path)

    def test_loaded_keys_can_sign_and_verify(self):
        with tempfile.NamedTemporaryFile(delete=False) as priv_tmp, \
             tempfile.NamedTemporaryFile(delete=False) as pub_tmp:

            priv_path = priv_tmp.name
            pub_path = pub_tmp.name

        try:
            save_private_key(self.private_key, priv_path)
            save_public_key(self.public_key, pub_path)

            loaded_priv = load_private_key(priv_path)
            loaded_pub = load_public_key(pub_path)

            signature = sign_data(self.data, loaded_priv)

            result = verify_signature(
                self.data,
                signature,
                loaded_pub
            )

            self.assertTrue(result)
        finally:
            os.remove(priv_path)
            os.remove(pub_path)

if __name__ == "__main__":
    unittest.main()