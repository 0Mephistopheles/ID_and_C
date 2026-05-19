import os
import sys
import time
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from Lab3.lab3 import rc5_encrypt, rc5_decrypt, derive_key, make_iv
from Lab4.lab4 import (
    generate_keys,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    rsa_encrypt_file,
    rsa_decrypt_file,
    chunk_size,
)

def benchmark(
    data: bytes,
    pub_key,
    priv_key,
    passphrase: str,
    seed: int = 3,
) -> dict:
    results: dict = {}

    t0 = time.perf_counter()
    rsa_enc = rsa_encrypt_file(data, pub_key)
    results['rsa_enc'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    rsa_decrypt_file(rsa_enc, priv_key)
    results['rsa_dec'] = time.perf_counter() - t0

    key = derive_key(passphrase)
    iv  = make_iv(seed)

    t0 = time.perf_counter()
    rc5_enc = rc5_encrypt(data, key, iv)
    results['rc5_enc'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    rc5_decrypt(rc5_enc, key)
    results['rc5_dec'] = time.perf_counter() - t0

    results['kb'] = len(data) / 1024
    return results

_SHARED_PRIV, _SHARED_PUB = generate_keys(1024)


class TestKeyGeneration(unittest.TestCase):

    def test_generate_returns_key_pair(self):
        priv, pub = generate_keys(1024)
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)

    def test_key_size_1024(self):
        priv, pub = generate_keys(1024)
        self.assertEqual(pub.key_size, 1024)

    def test_key_size_2048(self):
        priv, pub = generate_keys(2048)
        self.assertEqual(pub.key_size, 2048)

    def test_keys_are_different_each_call(self):
        _, pub1 = generate_keys(1024)
        _, pub2 = generate_keys(1024)
        from cryptography.hazmat.primitives import serialization
        pem1 = pub1.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pem2 = pub2.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertNotEqual(pem1, pem2)


class TestKeySerialization(unittest.TestCase):

    def test_save_and_load_private_key(self):
        priv, _ = generate_keys(1024)
        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as f:
            path = f.name
        try:
            save_private_key(priv, path)
            loaded = load_private_key(path)
            self.assertEqual(
                priv.private_numbers().d,
                loaded.private_numbers().d,
            )
        finally:
            os.unlink(path)

    def test_save_and_load_public_key(self):
        priv, pub = generate_keys(1024)
        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as f:
            path = f.name
        try:
            save_public_key(pub, path)
            loaded = load_public_key(path)
            self.assertEqual(
                pub.public_numbers().n,
                loaded.public_numbers().n,
            )
        finally:
            os.unlink(path)

    def test_load_nonexistent_key_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_private_key("/tmp/this_file_does_not_exist.pem")


class TestChunkSize(unittest.TestCase):

    def testchunk_size_1024(self):
        _, pub = generate_keys(1024)
        self.assertEqual(chunk_size(pub), 62)

    def testchunk_size_2048(self):
        _, pub = generate_keys(2048)
        self.assertEqual(chunk_size(pub), 190)


class TestRsaEncryptDecrypt(unittest.TestCase):
    def _roundtrip(self, plaintext: bytes) -> bytes:
        enc = rsa_encrypt_file(plaintext, _SHARED_PUB)
        return rsa_decrypt_file(enc, _SHARED_PRIV)

    def test_empty_bytes(self):
        self.assertEqual(self._roundtrip(b''), b'')

    def test_short_message(self):
        msg = b"Hello, RSA!"
        self.assertEqual(self._roundtrip(msg), msg)

    def test_exact_chunk_boundary(self):
        msg = os.urandom(62)
        self.assertEqual(self._roundtrip(msg), msg)

    def test_one_byte_over_chunk(self):
        msg = os.urandom(63)
        self.assertEqual(self._roundtrip(msg), msg)

    def test_multi_chunk(self):
        msg = os.urandom(300)
        self.assertEqual(self._roundtrip(msg), msg)

    def test_4kb_data(self):
        msg = os.urandom(4 * 1024)
        self.assertEqual(self._roundtrip(msg), msg)

    def test_encrypt_produces_different_ciphertext_each_time(self):
        msg = b"same plaintext"
        enc1 = rsa_encrypt_file(msg, _SHARED_PUB)
        enc2 = rsa_encrypt_file(msg, _SHARED_PUB)
        self.assertNotEqual(enc1, enc2)

    def test_wrong_key_raises(self):
        other_priv, _ = generate_keys(1024)
        enc = rsa_encrypt_file(b"secret", _SHARED_PUB)
        with self.assertRaises(Exception):
            rsa_decrypt_file(enc, other_priv)

    def test_tampered_ciphertext_raises(self):
        enc = bytearray(rsa_encrypt_file(b"secret", _SHARED_PUB))
        enc[-1] ^= 0xFF          # flip the last byte
        with self.assertRaises(Exception):
            rsa_decrypt_file(bytes(enc), _SHARED_PRIV)


class TestBenchmark(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = generate_keys(1024)
        cls.data = os.urandom(4 * 1024)   # 4 KB
        cls.results = benchmark(cls.data, cls.pub, cls.priv, "testpass")

    def test_returns_all_keys(self):
        expected = {'rsa_enc', 'rsa_dec', 'rc5_enc', 'rc5_dec', 'kb'}
        self.assertEqual(set(self.results.keys()), expected)

    def test_kb_value(self):
        self.assertAlmostEqual(self.results['kb'], 4.0, places=6)

    def test_all_timings_positive(self):
        for key in ('rsa_enc', 'rsa_dec', 'rc5_enc', 'rc5_dec'):
            self.assertGreater(self.results[key], 0, msg=f"{key} should be > 0")

    def test_timings_exist(self):
        for key in ('rsa_enc', 'rsa_dec', 'rc5_enc', 'rc5_dec'):
            self.assertGreater(self.results[key], 0)

    def test_benchmark_different_sizes(self):
        for kb in (1, 8):
            data = os.urandom(kb * 1024)
            res = benchmark(data, self.pub, self.priv, "pass")
            self.assertAlmostEqual(res['kb'], kb, places=6)

    def test_benchmark_with_custom_seed(self):
        res = benchmark(self.data, self.pub, self.priv, "pass", seed=42)
        self.assertIn('rsa_enc', res)

    def test_empty_data_does_not_crash(self):
        res = benchmark(b'', self.pub, self.priv, "pass")
        self.assertEqual(res['kb'], 0.0)

if __name__ == "__main__":
    print("Running benchmark demo (4 KB, 1024-bit RSA)…")
    priv, pub = generate_keys(1024)
    data = os.urandom(4 * 1024)
    res = benchmark(data, pub, priv, "demo-pass")

    def spd(kb_val: float, t: float) -> str:
        return f"{kb_val / t:,.0f} KB/s"

    print(f"\nData size       : {res['kb']:.0f} KB")
    print(f"RSA encrypt     : {res['rsa_enc']*1000:7.1f} ms   {spd(res['kb'], res['rsa_enc'])}")
    print(f"RSA decrypt     : {res['rsa_dec']*1000:7.1f} ms   {spd(res['kb'], res['rsa_dec'])}")
    print(f"RC5 encrypt     : {res['rc5_enc']*1000:7.1f} ms   {spd(res['kb'], res['rc5_enc'])}")
    print(f"RC5 decrypt     : {res['rc5_dec']*1000:7.1f} ms   {spd(res['kb'], res['rc5_dec'])}")

    enc_ratio = (res['kb'] / res['rc5_enc']) / (res['kb'] / res['rsa_enc'])
    dec_ratio = (res['kb'] / res['rc5_dec']) / (res['kb'] / res['rsa_dec'])
    print(f"\nRC5 / RSA enc   : {enc_ratio:,.0f}x faster")
    print(f"RC5 / RSA dec   : {dec_ratio:,.0f}x faster\n")

    print("Running unit tests…\n")
    unittest.main(argv=[''], exit=True, verbosity=2)