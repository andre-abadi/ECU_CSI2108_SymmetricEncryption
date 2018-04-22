"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""
# Main source for code:
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/hazmat/primitives/padding/

# Import libraries
import os
import sys
from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Preamble
print("CSI2108 Symmetric Encryption Tool\n")
# Input passphrase
passphrase = input("Please enter passphrase: ")
if len(passphrase) == 0:
    passphrase = "CSI2108"
    print("No passphrase detected, defaulting to: " + passphrase)
while ((sys.getsizeof(passphrase) * 8) != 256):
    passphrase = input(
        "{} is not 256, try again: "
        .format(sys.getsizeof(passphrase) * 8))
print("Passphrase is {} bits long".format(sys.getsizeof(passphrase) * 8))
# while len(passphrase) == 0:
#     passphrase = input("No passphrase detected! Please enter passphrase: ")
print("Your passphrase is: " + passphrase)
# Input filename
filename = input("Please enter a filename to be encrypted: ")
if len(filename) == 0:
    filename = "input.txt"
    print("No filename detecting, defaulting to: " + filename)
print("The filename to be encrypted is: " + filename)
file = open(filename, mode='r')
input = file.read()
print("The file was read and contained: " + input)
# Convert message to bytes
input = input.encode()
print("The message as bytes is: " + b64encode(input).decode())
# Pad message
padder = padding.PKCS7(16).padder()
padded = padder.update(input)
padded += padder.finalize()
print("The padded message is: " + b64encode(padded).decode())
# Generate Initialisation Vector (IV)
iv = os.urandom(16)
print("The Initialisation Vector (IV) is:  " + b64encode(iv).decode())
backend = default_backend()
settings = Cipher(algorithms.AES(passphrase), modes.CBC(iv), backend=backend)

encryptor = settings.encryptor()
decryptor = settings.decryptor()
# Create a secret message
message = "a secret message"
print(message)
# Convert message from String abstraction to literal bytes
message = message.encode()
# Pad the messaage to 256 bits

# Do the encryption
encrypted = encryptor.update(padded) + encryptor.finalize()
print(encrypted)
# Do the decryption
decrypted = decryptor.update(encrypted) + decryptor.finalize()
print(decrypted)
# Unpad the decrypted message
unpadder = padding.PKCS7(128).unpadder()
unpadded = unpadder.update(decrypted)
unpadded += unpadder.finalize()
plaintext = unpadded.decode()
print(plaintext)
