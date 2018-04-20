"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""
# Main source for code:
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/hazmat/primitives/padding/

# Import libraries
import os
# https://stackoverflow.com/questions/17958347/how-can-i-convert-a-python-urandom-to-a-string
from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


print("CSI2108 Symmetric Encryption Tool\n")
passphrase = input("Please enter passphrase: ")
if len(passphrase) == 0:
    passphrase = "TestPassphrase2018"
    print("No passphrase provided, using: " + passphrase)
# while len(passphrase) == 0:
#     passphrase = input("No passphrase detected! Please enter passphrase: ")
print("Your passphrase is: " + passphrase)
# Convert passphrase from String to bytes data type
filename = input("Please enter a filename to be encrypted: ")
if len(filename) == 0:
    filename = "input.txt"
    print("No filename provided, using: " + filename)
print("The filename to be encrypted is: " + filename)
file = open(filename, mode='r')
contents = file.read()
print("The file was read and contained: " + contents)


print("\nBegin hardcoded encryption-decryption sequence:")
# Object initialisation
key = os.urandom(32)
key_string = b64encode(key).decode()
print("The randomly generated key is: " + key_string)
iv = os.urandom(16)
iv_string = b64encode(iv).decode()
print("The randomly generated IV is:  " + iv_string)
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
# Do the encryption
encrypted = encryptor.update(padded) + encryptor.finalize()
print(encrypted)
# Do the decryption
decrypted = decryptor.update(encrypted) + decryptor.finalize()
print(decrypted)
# Unpad the decrypted message
unpadded = unpadder.update(decrypted)
unpadded += unpadder.finalize()
plaintext = unpadded.decode()
print(plaintext)
