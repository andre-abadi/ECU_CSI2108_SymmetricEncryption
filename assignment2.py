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


# Input passphrase
passphrase = input("Please enter passphrase: ")

# Check for some input, otherwise use a default
if len(passphrase) == 0:
    passphrase = "CSI2108"
    print("No passphrase detected, defaulting to: " + passphrase)
key = hashlib.sha256(passphrase).digest()
# Convert to bytes and check that passphrase is 256 bits (32 bytes) long

# Input filename
filename = input("Please enter a filename to be encrypted: ")
if len(filename) == 0:
    filename = "input.txt"
    print("No filename detecting, defaulting to: " + filename)
print("The filename to be encrypted is: " + filename)
# Open the file for reading
file = open(filename, mode='r')
message = file.read()
print("The file was read and contained: " + message)


# Convert message to bytes
message = message.encode()
print("The message as bytes is: " + b64encode(message).decode())
print("Message is {} bits long".format(sys.getsizeof(message) * 8))


# Pad message
isPadded = False
if (sys.getsizeof(message)*8) % 16 != 0:
    print("Padding")
    padder = padding.PKCS7(16).padder()
    padded = padder.update(message)
    padded += padder.finalize()
    message = padded
    isPadded = True
    print("The padded message is: " + b64encode(message).decode())
    print("Padded message is {} bits long".format(sys.getsizeof(message) * 8))


# Generate Initialisation Vector (IV)
iv = os.urandom(16)
print("The Initialisation Vector (IV) is:  " + b64encode(iv).decode())

# Initialise backend
backend = default_backend()
print("Passphrase is {} bits long".format(sys.getsizeof(passphrase) * 8))
print("Passphrase is {} bytes long".format(sys.getsizeof(passphrase)))
passphrase = os.urandom(32)
print("Random is {} bits long".format(sys.getsizeof(passphrase) * 8))
print("Random is {} bytes long".format(sys.getsizeof(passphrase)))
settings = Cipher(algorithms.AES(passphrase), modes.CBC(iv), backend=backend)
message = "a secret message"
message = message.encode()
# Create instance of encryptor and decryptor objects
encryptor = settings.encryptor()
decryptor = settings.decryptor()
print(message)
# Do the encryption
encrypted = encryptor.update(message) + encryptor.finalize()
print(encrypted)
# Do the decryption
decrypted = decryptor.update(encrypted) + decryptor.finalize()
print(decrypted)

# Unpad the decrypted message
if isPadded is True:
    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(decrypted)
    unpadded += unpadder.finalize()
    plaintext = unpadded.decode()
    print(plaintext)
