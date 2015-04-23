#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sjcl import SJCL
import unittest

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def test_encrypt_decrypt(self):
        message = "secret message to encrypt"
        cyphertext = SJCL().encrypt(message, "shared_secret")
        self.assertEqual(
            SJCL().decrypt(cyphertext, "shared_secret"),
            message
        )

    def test_decrypt_128(self):
        cyphertext = {
            'ks': 128,
            'cipher': 'aes',
            'mode': 'ccm',
            'v': 1,
            'adata': '',
            'iv': 'fR4fZKbjsZOrzDyjCYdEQw==',
            'salt': '5IiimlH8JvY=',
            'ts': 64,
            'iter': 1000,
            'ct': 'V8BYrUdurq1/Qx/EX8EBliKDKa6XB93dZ6QOFSelw77Q'
        }
        self.assertEqual(
            SJCL().decrypt(cyphertext, "shared_secret"),
            "secret message to encrypt"
        )

    def test_decrypt_192(self):
        cyphertext = {
            'ks': 192,
            'cipher': 'aes',
            'mode': 'ccm',
            'v': 1,
            'adata': '',
            'iv': '3NCuY8Ev/Fbuf+2WqoQCDg==',
            'salt': 'QL3iSh2PnVI=',
            'ts': 64,
            'iter': 1000,
            'ct': '4/BcukcCJHgQXQA3QhJ3RTykynj3g1do49+BIW2Nge0S'
        }
        self.assertEqual(
            SJCL().decrypt(cyphertext, "shared_secret"),
            "secret message to encrypt"
        )

    def test_decrypt_256(self):
        cyphertext = {
            'ks': 256,
            'cipher': 'aes',
            'mode': 'ccm',
            'v': 1,
            'adata': '',
            'iv': 'bgEVvR8Hw9kY2UF0RcWUcQ==',
            'salt': 'QL3iSh2PnVI=',
            'ts': 64,
            'iter': 1000,
            'ct': 'lIFzbDGF9aflXHrZfZIF4+zN7r3nCUtSf8R5ztGM0nH0'
        }
        self.assertEqual(
            SJCL().decrypt(cyphertext, "shared_secret"),
            "secret message to encrypt"
        )

    def test_decrypt_nopad(self):
        cyphertext = {
            'ks': 128,
            'cipher': 'aes',
            'mode': 'ccm',
            'v': 1,
            'adata': '',
            'iv': 'fR4fZKbjsZOrzDyjCYdEQw',
            'salt': '5IiimlH8JvY',
            'ts': 64,
            'iter': 1000,
            'ct': 'V8BYrUdurq1/Qx/EX8EBliKDKa6XB93dZ6QOFSelw77Q'
        }
        self.assertEqual(
            SJCL().decrypt(cyphertext, "shared_secret"),
            "secret message to encrypt"
        )

if __name__ == '__main__':
    unittest.main()
