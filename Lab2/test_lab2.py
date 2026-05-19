import unittest
import hashlib
from Lab2.lab2 import md5


class TestMD5(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(
            md5(b""),
            "D41D8CD98F00B204E9800998ECF8427E"
        )

    def test_a(self):
        self.assertEqual(
            md5(b"a"),
            "0CC175B9C0F1B6A831C399E269772661"
        )

    def test_abc(self):
        self.assertEqual(
            md5(b"abc"),
            "900150983CD24FB0D6963F7D28E17F72"
        )

    def test_message_digest(self):
        self.assertEqual(
            md5(b"message digest"),
            "F96B697D7CB7938D525A2F31AAF161D0"
        )

    def test_alphabet(self):
        self.assertEqual(
            md5(b"abcdefghijklmnopqrstuvwxyz"),
            "C3FCD3D76192E4007DFB496CCA67E13B"
        )

    def test_compare_with_hashlib(self):
        data = b"OpenAI Test String"

        self.assertEqual(
            md5(data),
            hashlib.md5(data).hexdigest().upper()
        )


if __name__ == "__main__":
    unittest.main()