"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""


# Import libraries
import os
import hashlib
from base64 import b64encode
from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _createKey():
    # Ask for an input password
    password = input("Please enter a passphrase: ")
    # Use a default (for testing) if no input is received
    if len(password) == 0:
        password = "CSI2108"
        print("No passphrase detected, defaulting to: " + password)
    # Convert the password to bytes and then SHA256 it
    hashedPass = hashlib.sha256(password.encode()).digest()
    return hashedPass


def _readMsgFile():
    filename = input("Please enter a file to read: ")
    if len(filename) == 0:
        filename = "input.txt"
        print("No filename detected, defaulting to: " + filename)
    try:
        file = open(filename, mode='r')
        message = file.read()
        message = message.encode()
        return message
    except FileNotFoundError:
        input("Unable to find your file. Press ENTER to exit.")
        quit()


def _padMessage(msg: bytes):
    # Start the padded message with the message
    paddedMsg = bytes(msg)
    print("Message length is: " + str(len(msg)))
    modulo = (len(msg)) % 16
    print("Remainder is: " + str(modulo))
    # Work out how many bytes short of a multiple of 16 are needed filled
    padlength = 16 - modulo
    print("Pad length is: " + str(padlength))
    # Convert the magic number to a string, then bytes
    padChar = str(padlength)
    padBytes = bytes([padlength])
    # Start a counter
    count = 0
    while (count < padlength):
        paddedMsg += padBytes
        count += 1
    return (paddedMsg, padChar)


def _encrypt(msg: str, kee: str, vec: str):
    padded = _padMessage(msg)
    paddedMessage = padded[0]
    pad = padded[1]
    backend = default_backend()
    cipher = Cipher(algorithms.AES(kee), modes.CBC(vec), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(paddedMessage) + encryptor.finalize()
    print(b64encode(encrypted).decode())
    return (encrypted, pad)


def _writeCryptoFile(encrypted: bytes, vector: bytes, padchar: int):
    fname = input("Please enter a filename for the encryption output: ")
    # If no input provided, use a default (for development testing)
    if len(fname) == 0:
        fname = "enciphered.txt"
        print("No filename detected, defaulting to: " + fname)
    try:
        file = open(fname, mode='w')
        encrypted = b64encode(encrypted).decode()
        print(encrypted)
        vector = b64encode(vector).decode()
        file.write("-----BEGIN AES256-CBC MESSAGE-----\n\n")
        file.write(encrypted)
        print(encrypted)
        file.write("\n\n-----END AES256-CBC MESSAGE-----\n\n")
        file.write("-----BEGIN AES256-CBC INITIALISATION VECTOR-----\n\n")
        file.write(vector)
        file.write("\n\n-----END AES256-CBC INITIALISATION VECTOR-----\n\n")
        file.write("-----BEGIN PADDING CHARACTER-----\n\n")
        file.write(padchar)
        file.write("\n\n-----END AES256-CBC INITIALISATION VECTOR-----\n\n")
    except FileNotFoundError:
        input("Unable to find file. Press ENTER to exit.")
        quit()


def _encryptWrapper():
    # Create a key
    key = _createKey()
    # Read the message from the message file
    message = _readMsgFile()
    # Generate an IV
    iv = os.urandom(16)
    # Encrypt the message using the IV and the key
    enciphered = _encrypt(message, key, iv)
    ciphertext = enciphered[0]
    padCharacter = enciphered[1]
    # Write the encrypted message and IV to file
    _writeCryptoFile(ciphertext, iv, padCharacter)
    input("Done. Press ENTER to exit.")


def _readCryptoFile():
    # Prompt for input for name of a file to be opened
    filename = input("Please enter file of encrypted data to read: ")
    # If no input provided, use a default (for development testing)
    if len(filename) == 0:
        filename = "enciphered.txt"
        print("No filename detected, defaulting to: " + filename)
    try:
        file = open(filename, mode='r')
        # Convert opened file into a list of lines, each as Strings
        lines = file.readlines()
        # Pull out the ciphertext alawys on the 3rd line, stripping it of EOL
        encrypted = lines[2].strip()
        print(encrypted)
        # Decode it from base64 string back into bytes
        encrypted = b64decode(encrypted)
        print(encrypted)
        # print(encrypted)
        # Pull out the IV alawys on the 9th line, stripping it of EOL
        vector = lines[8].strip()
        # Decode it from base64 string back into bytes
        vector = b64decode(vector)
        # Return a tuple of the encrypted text and the IV
        return (encrypted, vector)
    # Detect known error if the file is not found
    except FileNotFoundError:
        input("Unable to find that file. Press ENTER to exit.")
        quit()


def _unPadMessage(msg: str):
    padlength = msg[-1]
    padlength = int(padlength)
    unpaddedMsg = msg[:-padlength]
    return unpaddedMsg


def _decrypt(msg: str, kee: str, vec: str):
    backend = default_backend()
    settings = Cipher(algorithms.AES(kee), modes.CBC(vec), backend=backend)
    decryptor = settings.decryptor()
    decrypted = decryptor.update(msg) + decryptor.finalize()
    plaintext = _unPadMessage(decrypted)
    plaintext = plaintext.decode()
    return plaintext


def _decryptWrapper():
    # Create a key
    key = _createKey()
    # Read the encrypted message and IV from the nominated file
    cipherdata = _readCryptoFile()
    # Seperate out the returned Tuple into the encrypted message and IV
    ciphertext = cipherdata[0]
    vector = cipherdata[1]
    # Attempt the decryption with the given values
    try:
        decrypted = _decrypt(ciphertext, key, vector)
        # Print the decrypted message in a PGP-inspired way
        print("\n-----BEGIN DECRYPTED MESSAGE-----\n")
        print(decrypted)
        print("\n-----END DECRYPTED MESSAGE------\n")
    # Detect known error if any of the decryption values are incorrect
    except ValueError:
        input("Your key was incorrect. Press ENTER to exit.")
        quit()


print("CSI2108 AES256-CBC SYMMETRIC ENCRYPTION TOOL")
choice = "0"
while (choice != "1") and (choice != "2"):
    choice = input("Please enter 1 to encrypt or 2 to decrypt a file: ")
if (choice == "1"):
    _encryptWrapper()
if (choice == "2"):
    _decryptWrapper()
