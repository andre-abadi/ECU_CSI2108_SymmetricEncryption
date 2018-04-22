"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""
# Main source for code:
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/hazmat/primitives/padding/

# Import libraries
import os
import hashlib
from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _createKey(passphrase):
    if len(passphrase) == 0:
        passphrase = "CSI2108"
        print("No passphrase detected, defaulting to: " + passphrase)
    key = hashlib.sha256(passphrase.encode()).digest()
    return key


def _createMessage(filename):
    if len(filename) == 0:
        filename = "input.txt"
        print("No filename detected, defaulting to: " + filename)
    file = open(filename, mode='r')
    message = file.read()
    message = message.encode()
    return message


def _encrypt(message):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message)
    padded += padder.finalize()
    backend = default_backend()
    settings = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = settings.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return encrypted


def _decrypt(ciphertext):
    backend = default_backend()
    settings = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = settings.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    # Unpad the decrypted message
    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(decrypted)
    unpadded += unpadder.finalize()
    plaintext = unpadded.decode()
    return plaintext


# Preamble
print("CSI2108 Symmetric Encryption Tool\n")
# Input passphrase
passphrase = input("Please enter passphrase: ")
key = _createKey(passphrase)
# Input filename
filename = input("Please enter a filename to be encrypted: ")
message = _createMessage(filename)
# Generate Initialisation Vector (IV)
iv = os.urandom(16)
print("The Initialisation Vector (IV) is:  " + b64encode(iv).decode())
secret_message = _encrypt(message)
deciphered = _decrypt(secret_message)
