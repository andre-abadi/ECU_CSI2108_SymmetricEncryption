"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""
# Main source for code:
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/hazmat/primitives/padding/

# Import libraries
import os
import sys
import hashlib
from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Preamble
print("CSI2108 Symmetric Encryption Tool\n")
isPadded = False


def _createKey(passphrase):
    if len(passphrase) == 0:
        passphrase = "CSI2108"
        print("No passphrase detected, defaulting to: " + passphrase)
    key = hashlib.sha256(passphrase.encode()).digest()
    return key


def _createMessage(filename):
    if len(filename) == 0:
        filename = "input.txt"
        print("No filename detecting, defaulting to: " + filename)
    # Open the file for reading
    file = open(filename, mode='r')
    message = file.read()
    message = message.encode()
    return message


# Input passphrase
passphrase = input("Please enter passphrase: ")
key = _createKey(passphrase)
# Input filename
filename = input("Please enter a filename to be encrypted: ")
message = _createMessage(filename)
# Generate Initialisation Vector (IV)
iv = os.urandom(16)
print("The Initialisation Vector (IV) is:  " + b64encode(iv).decode())

# Encryption
if (sys.getsizeof(message)*8) % 128 != 0:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message)
    padded += padder.finalize()
    message = padded
    isPadded = True
backend = default_backend()
settings = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = settings.encryptor()
encrypted = encryptor.update(message) + encryptor.finalize()


# Decryption
backend = default_backend()
settings = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
decryptor = settings.decryptor()
decrypted = decryptor.update(encrypted) + decryptor.finalize()
# Unpad the decrypted message
if isPadded is True:
    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(decrypted)
    unpadded += unpadder.finalize()
    plaintext = unpadded.decode()
    print(plaintext)
