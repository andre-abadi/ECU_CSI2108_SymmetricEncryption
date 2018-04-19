# CSI2108 Semester 1 2018
# Assessable Workshop - Symmetric Encryption

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# Setup
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

#Initialise
key = os.urandom(32)
iv = os.urandom(16)

# Creat a new instance of a Cipher object
settings = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

# Create an instance of an encryptor object
encryptor = settings.encryptor()
decryptor = settings.decryptor()

# Create a secret message
message = "a secret message"
# Print said message
print(message)

# Convert message from String abstraction to literal bytes
message = message.encode()
# Print the variable (it will print as a String prepended by 'b')
print(message)

#Actually do the encryption
ciphertext = encryptor.update(message) + encryptor.finalize()
print(ciphertext)

# Creat an instance of a decryptor object
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
plaintext = plaintext.decode()
print(plaintext)
