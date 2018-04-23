"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""


# Import libraries
import os
import hashlib
from base64 import b64encode
from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _encrypt(msg: str, kee: str, vec: str):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(msg)
    padded += padder.finalize()
    backend = default_backend()
    cipher = Cipher(algorithms.AES(kee), modes.CBC(vec), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return encrypted


def _decrypt(msg: str, kee: str, vec: str):
    backend = default_backend()
    settings = Cipher(algorithms.AES(kee), modes.CBC(vec), backend=backend)
    decryptor = settings.decryptor()
    decrypted = decryptor.update(msg) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(decrypted)
    unpadded += unpadder.finalize()
    plaintext = unpadded.decode()
    return plaintext


def _createKey():
    password = input("Please enter passphrase: ")
    if len(password) == 0:
        password = "CSI2108"
        print("No passphrase detected, defaulting to: " + password)
    hashedPass = hashlib.sha256(password.encode()).digest()
    return hashedPass


def _readMsgFile():
    filename = input("Please enter a file to read: ")
    if len(filename) == 0:
        filename = "input.txt"
        print("No filename detected, defaulting to: " + filename)
    file = open(filename, mode='r')
    message = file.read()
    message = message.encode()
    return message


def _writeCryptoFile(encrypted: bytes, vector: bytes):
    fname = input("Please enter a filename for the encryption output: ")
    if len(fname) == 0:
        fname = "enciphered.txt"
        print("No filename detected, defaulting to: " + fname)
    file = open(fname, mode='w')
    encrypted = b64encode(encrypted).decode()
    vector = b64encode(vector).decode()
    file.write("-----BEGIN AES256-CBC MESSAGE-----\n\n")
    file.write(encrypted)
    file.write("\n\n-----END AES256-CBC MESSAGE-----\n\n")
    file.write("-----BEGIN AES256-CBC INITIALISATION VECTOR-----\n\n")
    file.write(vector)
    file.write("\n\n-----END AES256-CBC INITIALISATION VECTOR-----\n\n")


def _readCryptoFile():
    fname = input("Please enter file of encrypted data to read: ")
    if len(fname) == 0:
        fname = "enciphered.txt"
        print("No filename detected, defaulting to: " + fname)
    file = open(fname, mode='r')
    lines = file.readlines()
    encrypted = lines[2].strip()
    encrypted = b64decode(encrypted)
    vector = lines[8].strip()
    vector = b64decode(vector)
    return (encrypted, vector)


def _encryptWrapper():
    key = _createKey()
    message = _readMsgFile()
    iv = os.urandom(16)
    secret_message = _encrypt(message, key, iv)
    _writeCryptoFile(secret_message, iv)
    print("Done!\n")


def _decryptWrapper():
    key = _createKey()
    cipherdata = _readCryptoFile()
    ciphertext = cipherdata[0]
    vector = cipherdata[1]
    try:
        decrypted = _decrypt(ciphertext, key, vector)
        print("\n-----BEGIN DECRYPTED MESSAGE-----\n")
        print(decrypted)
        print("\n-----END DECRYPTED MESSAGE------\n")
    except ValueError:
        print("Your key was incorrect! Aborting program.\n")


print("CSI2108 AES256-CBC SYMMETRIC ENCRYPTION TOOL")
print("This tool will encrypt or decrypt a chosen file.")
choice = "0"
while (choice != "1") and (choice != "2"):
    choice = input("Please enter 1 for encryption or 2 for decryption: ")
if (choice == "1"):
    _encryptWrapper()
if (choice == "2"):
    _decryptWrapper()
