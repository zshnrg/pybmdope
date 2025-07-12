import unittest
from bmdope.bmdope import BMDOPE

class TestBMDOPE(unittest.TestCase):
    def setUp(self):
        self.key = b"W:]-I~Yzx;?E506h"  # 16-character key
        self.bmdope = BMDOPE(self.key)
        
    def test_encrypt_block(self):
        block = b"test"
        key = b"1234567890abcdef"
        encrypted = self.bmdope.encrypt_block(block, key)
        self.assertIsInstance(encrypted, bytes)
        self.assertNotEqual(encrypted, block)

    def test_encrypt_block_invalid_key(self):
        block = b"test"
        key = b"short_key"
        with self.assertRaises(ValueError):
            self.bmdope.encrypt_block(block, key)

    def test_encrypt_block_invalid_block_size(self):
        block = b"toolongblock"
        key = b"1234567890abcdef"
        with self.assertRaises(ValueError):
            self.bmdope.encrypt_block(block, key)

    def test_decrypt_block(self):
        block = b"test"
        key = b"1234567890abcdef"
        encrypted = self.bmdope.encrypt_block(block, key)
        decrypted = self.bmdope.decrypt_block(encrypted, key)
        self.assertEqual(decrypted, block)

    def test_decrypt_block_invalid_key(self):
        encrypted = b"110010101011"
        key = b"short_key"
        with self.assertRaises(ValueError):
            self.bmdope.decrypt_block(encrypted, key)

if __name__ == "__main__":
    unittest.main()
