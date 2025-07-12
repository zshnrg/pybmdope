import unittest
from bmdope.key import reshuffle, split_key, rotate_left, rotate_right

class TestKeyModule(unittest.TestCase):
    def test_reshuffle(self):
        input_str = "abcdefgh12345678"
        result = reshuffle(input_str)
        self.assertEqual(len(result), 16)
        self.assertNotEqual(result, input_str)

    def test_reshuffle_invalid_length(self):
        with self.assertRaises(ValueError):
            reshuffle("short")

    def test_split_key(self):
        key = "abcdefgh12345678"
        parts, shifts = split_key(key)
        self.assertEqual(len(parts), 4)
        self.assertEqual(len(shifts), 4)
        self.assertEqual(parts[0], "abcd")
        self.assertEqual(parts[1], "efgh")
        self.assertEqual(parts[2], "1234")
        self.assertEqual(parts[3], ''.join([chr(ord('a') ^ ord('e') ^ ord('1')),
                                           chr(ord('b') ^ ord('f') ^ ord('2')),
                                           chr(ord('c') ^ ord('g') ^ ord('3')),
                                           chr(ord('d') ^ ord('h') ^ ord('4'))]))

    def test_split_key_invalid_length(self):
        with self.assertRaises(ValueError):
            split_key("short")

    def test_rotate_left(self):
        self.assertEqual(rotate_left(0b10101010, 3), 0b01010101)
        self.assertEqual(rotate_left(0b11110000, 4), 0b00001111)

    def test_rotate_right(self):
        self.assertEqual(rotate_right(0b10101010, 3), 0b01010101)
        self.assertEqual(rotate_right(0b11110000, 4), 0b00001111)

if __name__ == "__main__":
    unittest.main()
