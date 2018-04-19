"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""
# Main source for code:
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

# Import libraries
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Object initialisation
key = os.urandom(32)
iv = os.urandom(16)
backend = default_backend()
settings = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = settings.encryptor()
decryptor = settings.decryptor()

# Create a secret message
message = "a secret message"
print(message)
# Convert message from String abstraction to literal bytes
message = message.encode()

# https://cryptography.io/en/latest/hazmat/primitives/padding/
padder = padding.PKCS7(256).padder()

# Actually do the encryption
ciphertext = encryptor.update(message) + encryptor.finalize()
print(ciphertext)

# Do the decryption
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
plaintext = plaintext.decode()
print(plaintext)

# Input testing
input = input("Please enter something:")
print(input)
