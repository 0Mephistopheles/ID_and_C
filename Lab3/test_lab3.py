import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from Lab1.lab1 import lcg
from Lab2.lab2 import md5
from Lab3.lab3 import (
    derive_key, make_iv, expand,
    enc_block, dec_block,
    rc5_encrypt, rc5_decrypt,
    BLOCK,
)


class TestDeriveKey(unittest.TestCase):
    def test_uses_md5(self):
        pw = "passphrase"
        self.assertEqual(derive_key(pw), bytes.fromhex(md5(pw.encode())))

    def test_different_passphrases(self):
        self.assertNotEqual(derive_key("abc"), derive_key("xyz"))


class TestMakeIV(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(make_iv(3)), BLOCK)

    def test_reproducible(self):
        self.assertEqual(make_iv(3), make_iv(3))

    def test_different_seeds(self):
        self.assertNotEqual(make_iv(3), make_iv(7))

    def test_uses_lcg(self):
        nums = lcg(3, seed=5)
        expected = b''.join(n.to_bytes(3, 'little') for n in nums)[:BLOCK]
        self.assertEqual(make_iv(5), expected)


class TestRC5Block(unittest.TestCase):
    KEY = derive_key("unittest")

    def test_roundtrip(self):
        S = expand(self.KEY)
        for pt in [b'\x00'*8, b'\xff'*8, bytes(range(8))]:
            self.assertEqual(dec_block(enc_block(pt, S), S), pt)

    def test_deterministic(self):
        S = expand(self.KEY)
        pt = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.assertEqual(enc_block(pt, S), enc_block(pt, S))

    def test_different_keys(self):
        S1 = expand(derive_key("key1"))
        S2 = expand(derive_key("key2"))
        pt = b'\xAB' * 8
        self.assertNotEqual(enc_block(pt, S1), enc_block(pt, S2))


class TestCBCPad(unittest.TestCase):
    KEY = derive_key("testkey")
    IV  = make_iv(3)

    def _rt(self, msg):
        self.assertEqual(rc5_decrypt(rc5_encrypt(msg, self.KEY, self.IV), self.KEY), msg)

    def test_empty(self):           self._rt(b'')
    def test_one_byte(self):        self._rt(b'A')
    def test_exact_block(self):     self._rt(b'B' * BLOCK)
    def test_multi_block(self):     self._rt(b'Hello world! ' * 20)
    def test_large(self):           self._rt(b'x' * 10000)

    def test_iv_stored_first_block(self):
        enc = rc5_encrypt(b'data', self.KEY, self.IV)
        self.assertGreater(len(enc), BLOCK)

    def test_different_ivs_differ(self):
        iv2 = make_iv(99)
        e1 = rc5_encrypt(b'same', self.KEY, self.IV)
        e2 = rc5_encrypt(b'same', self.KEY, iv2)
        self.assertNotEqual(e1, e2)

    def test_wrong_key_corrupts(self):
        enc = rc5_encrypt(b'secret', self.KEY, self.IV)
        bad = rc5_decrypt(enc, derive_key("wrong"))
        self.assertNotEqual(bad, b'secret')


if __name__ == "__main__":
    unittest.main(verbosity=2)