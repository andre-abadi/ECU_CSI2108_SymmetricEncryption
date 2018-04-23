"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""


# Import libraries
import os
import hashlib
from base64 import b64encode
from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _createKey():
    pwd = input("Please enter passphrase: ")
    if len(pwd) == 0:
        pwd = "CSI2108"
        print("No passphrase detected, defaulting to: " + pwd)
    sha = hashlib.sha256(pwd.encode()).digest()
    return sha


def _readMsgFile():
    fnm = input("Please enter a file to read: ")
    if len(fnm) == 0:
        fnm = "input.txt"
        print("No filename detected, defaulting to: " + fnm)
    fil = open(fnm, mode='r')
    txt = fil.read()
    txt = txt.encode()
    return txt


def _writeCrypto(enc: bytes, vec: bytes):
    fnm = input("Please enter a filename for the encryption output: ")
    if len(fnm) == 0:
        fnm = "enciphered.txt"
        print("No filename detected, defaulting to: " + fnm)
    fil = open(fnm, mode='w')
    enc = b64encode(enc).decode()
    vec = b64encode(vec).decode()
    fil.write("-----BEGIN AES256-CBC MESSAGE-----\n\n")
    fil.write(enc)
    fil.write("\n\n-----END AES256-CBC MESSAGE-----\n\n")
    fil.write("-----BEGIN AES256-CBC INITIALISATION VECTOR-----\n\n")
    fil.write(vec)
    fil.write("\n\n-----END AES256-CBC INITIALISATION VECTOR-----\n\n")


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
    # Unpad the decrypted message
    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(decrypted)
    unpadded += unpadder.finalize()
    plaintext = unpadded.decode()
    return plaintext


def _readCrypto():
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


# Preamble
print("CSI2108 AES256-CBC SYMMETRIC ENCRYPTION TOOL\n")
print("This tool will encrypt or decrypt a chosen file.\n")
choice = "0"
while (choice != "1") and (choice != "2"):
    print("Please enter 1 for encryption or 2 for decryption:\n")
    choice = input()
if (choice == "1"):
    print
    key = _createKey()
    message = _readMsgFile()
    iv = os.urandom(16)
    secret_message = _encrypt(message, key, iv)
    _writeCrypto(secret_message, iv)
if (choice == "2"):
    key = _createKey()
    cipherdata = _readCrypto()
    ciphertext = cipherdata[0]
    vector = cipherdata[1]
    decrypted = _decrypt(ciphertext, key, vector)
    print(decrypted)
