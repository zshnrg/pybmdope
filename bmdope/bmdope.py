"""
bmdope.py
This file is main module of py-bmdope.
py-bmdope is a Python package for Block Metadata-Driven Order-Preserving Encryption (BMDOPE).
It provides functionalities for encrypting and decrypting data using the BMDOPE algorithm.
"""

from bmdope.key import split_key

class BMDOPE:
    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            raise ValueError("Key must be a bytes object.")
        if len(key) != 16:
            raise ValueError("Key must be exactly 16 characters long.")
        self.key = key
        self.__current_key = key
    
    def encrypt_block(self, block: bytes, key: bytes) -> bytes:
        """
        Encrypts a 4-byte block using a 16-character key.
        
        The function processes the block through a series of additions and bitwise
        left shifts. The operations are determined by splitting the key into
        different parts. The final integer value is converted to its binary
        string representation and then encoded into bytes.
        
        Args:
            block (bytes): The data block to be encrypted, with a maximum size of 4 bytes.
            key (str): The encryption key, which must be exactly 16 characters long.
        
        Returns:
            bytes: The encrypted data as a binary string encoded in UTF-8.
        
        Raises:
            ValueError: If the provided key is not in bytes format, 
                        is not 16 characters long, or if the block size exceeds 4 bytes.
        """
        if not isinstance(key, bytes):
            raise ValueError("Key must be a bytes object.")
        if len(key) != 16:
            raise ValueError("Invalid key size.")
        if len(block) > 4:
            raise ValueError("Block size must not exceed 4 bytes.")
        
        parts, shifts = split_key(key)
        value = int.from_bytes(block, 'big')
        
        for i in range(4):
            value += int.from_bytes(parts[i])
            if i != 3:
                shift_value = shifts[i] & 0b11111
                value <<= shift_value
        
        return bin(value)[2:].encode()

    def decrypt_block(self, encrypted_value: bytes, key: bytes) -> bytes:
        """
        Decrypts a single block of data using a provided key.
        
        This function reverses the encryption process by performing a series of
        subtractions and right bit shifts on the input value. The operations are
        derived from the provided 16-character key. The input `encrypted_value`
        is expected to be a byte string representing an integer in binary format.
        
        Args:
            encrypted_value (bytes): The encrypted block to be decrypted. This should
                be a byte string containing the binary representation of the
                encrypted integer.
            key (str): The 16-character string key used for decryption.
        
        Returns:
            bytes: The decrypted data as a 4-byte block in big-endian format.
        
        Raises:
            ValueError: If the provided key is in bytes format or is not 16 characters long.
        """
        if not isinstance(key, bytes):
            raise ValueError("Key must be a bytes object.")
        if len(key) != 16:
            raise ValueError("Invalid key size.")
        
        parts, shifts = split_key(key)
        value = int(encrypted_value.decode(), 2)
        
        for i in range(3, -1, -1):
            if i != 3:
                shift_value = shifts[i] & 0b11111
                value >>= shift_value
            value -= int.from_bytes(parts[i])
        
        byte_length = (value.bit_length() + 7) // 8 if value > 0 else 1
        return value.to_bytes(byte_length, 'big')