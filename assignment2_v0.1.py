"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""
# Main source for code:
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/hazmat/primitives/padding/

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
padder = padding.PKCS7(128).padder()
unpadder = padding.PKCS7(128).unpadder()
encryptor = settings.encryptor()
decryptor = settings.decryptor()

# Create a secret message
message = "a secret message"
print(message)
# Convert message from String abstraction to literal bytes
message = message.encode()
# Pad the messaage to 256 bits
padded = padder.update(message)
padded += padder.finalize()
print(padded)

# Actually do the encryption
encrypted = encryptor.update(padded) + encryptor.finalize()
print(encrypted)

# Do the decryption
decrypted = decryptor.update(encrypted) + decryptor.finalize()
print(decrypted)

unpadded = unpadder.update(decrypted)
unpadded += unpadder.finalize()
plaintext = unpadded.decode()
print(plaintext)

print("test")
