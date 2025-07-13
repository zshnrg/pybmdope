# pybmdope

BMDOPE (Block Metadata-Driven Order-Preserving Encryption) is a custom encryption library designed to process data securely while preserving the order of encrypted blocks.

## Overview

BMDOPE is designed for scenarios where maintaining the order of encrypted data is critical, such as database indexing or range queries on encrypted data. It achieves this by encrypting data in blocks and using metadata to preserve the order of the blocks during encryption and decryption.

### Algorithm

1. **Block-Based Encryption**: Data is divided into fixed-size blocks, and each block is encrypted individually using a key.
2. **Metadata Handling**: Metadata is generated during encryption to store information about the length of each encrypted block. This metadata is encrypted separately to ensure security.
3. **Order Preservation**: The encryption algorithm ensures that the lexicographical order of the plaintext blocks is preserved in the encrypted blocks.
4. **Key Management**: The encryption key is reshuffled after processing each block to enhance security.

### Use Cases

- **Encrypted Databases**: Perform range queries or sorting operations on encrypted data without decrypting it.
- **Secure Indexing**: Maintain the order of encrypted data for efficient indexing and retrieval.
- **Data Transmission**: Securely transmit ordered data while preserving its structure.

## Installation

### From PyPI

Install the package directly from PyPI:

```bash
pip install pybmdope
```

### From Source

To install the package from the source, use:

```bash
pip install -e .
```

This will install the package in editable mode, allowing you to make changes to the source code and use them immediately.

## Usage

### Example

```python
from pybmdope.bmdope import BMDOPE

# Initialize BMDOPE with a 16-character key
key = b"W:]-I~Yzx;?E506h"
bmdope = BMDOPE(key)

# Data to encrypt
data = b"example data for encryption"

# Encrypt the data
encrypted_data = bmdope.encrypt(data)
print(f"Encrypted Data: {encrypted_data}")

# Decrypt the data
decrypted_data = bmdope.decrypt(encrypted_data)
print(f"Decrypted Data: {decrypted_data.decode('utf-8')}")
```

## Testing

Unit tests are provided for all modules and integration. Run the tests using:

```bash
pytest
```

## TODO

- Replace binary string representation (e.g., `b'1010101'`) with `bitarray` for improved performance and flexibility.

## License

This project is licensed under the MIT License.
