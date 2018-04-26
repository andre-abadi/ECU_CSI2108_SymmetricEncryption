"""CSI2108 Semester 1 2018: Assessable Workshop - Symmetric Encryption."""


# Import libraries
import os
from base64 import binascii
from base64 import b64encode
from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _createKey():
    # Ask for an input password
    password = input("Please enter a passphrase: ")
    # Strip EOL & any trailing whitespace
    password = password.strip()
    # Convert password string to bytes
    passbytes = password.encode()
    # If the password is not 256 bits (32 bytes) then try again
    while (len(passbytes) != 32):
        # Find out the length in bits of the supplied, incorrect password
        passbits = str(len(passbytes.strip()) * 8)
        # Tell the user how many bits the wrong password was
        print("Password was " + passbits + "-bits and should be 256-bits.")
        # Get a new password
        password = input("Please enter a passphrase: ")
        # Strip EOL & any trailing whitespace
        password = password.strip()
        # Convert password string to bytes
        passbytes = password.encode()
    return passbytes


def _readMsgFile():
    # status boolean so that excepttions cause repeat of while loop
    done = False
    while not done:
        try:
            filename = input("Please enter a file to read: ")
            file = open(filename, mode='r')
            message = file.read()
            message = message.encode()
            return message
            done = True
        except FileNotFoundError:
            print("Unable to find your file. Try Again.")


def _padMessage(msg: bytes):
    # Start the padded message with the message
    paddedMsg = bytes(msg)
    modulo = (len(msg)) % 16
    # Work out how many bytes short of a multiple of 16 are needed filled
    padlength = 16 - modulo
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
    # call the unpadding function
    padded = _padMessage(msg)
    # seperate out variables from above returned tuple
    paddedMessage = padded[0]
    pad = padded[1]
    backend = default_backend()
    cipher = Cipher(algorithms.AES(kee), modes.CBC(vec), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(paddedMessage) + encryptor.finalize()
    return (encrypted, pad)


def _writeCryptoFile(encrypted: bytes, vector: bytes, padchar: int):
    # status boolean so that excepttions cause repeat of while loop
    done = False
    while not done:
        try:
            fname = input("Please enter a filename for encrypted output: ")
            file = open(fname, mode='w')
            encrypted = b64encode(encrypted).decode()
            vector = b64encode(vector).decode()
            file.write("-----BEGIN AES256-CBC MESSAGE-----\n\n")
            file.write(encrypted)
            file.write("\n\n-----END AES256-CBC MESSAGE-----\n\n")
            file.write("-----BEGIN AES256-CBC INITIALISATION VECTOR-----\n\n")
            file.write(vector)
            file.write(
                "\n\n-----END AES256-CBC INITIALISATION VECTOR-----\n\n")
            file.write("-----BEGIN PADDING CHARACTER-----\n\n")
            file.write(padchar)
            file.write(
                "\n\n-----END AES256-CBC INITIALISATION VECTOR-----\n\n")
            done = True
        except FileNotFoundError:
            print("Unable to open \"" + fname + "\". Please try again.")


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
    # status boolean so that excepttions cause repeat of while loop
    done = False
    while not done:
        try:
            # Prompt for input for name of a file to be opened
            filename = input("Please enter file of encrypted data to read: ")
            file = open(filename, mode='r')
            # Convert opened file into a list of lines, each as Strings
            lines = file.readlines()
            # Pull out the ciphertext alawys on the 3rd line
            encrypted = lines[2].strip()
            # Decode it from base64 string back into bytes
            encrypted = b64decode(encrypted)
            # print(encrypted)
            # Pull out the IV alawys on the 9th line, stripping it of EOL
            vector = lines[8].strip()
            # Decode it from base64 string back into bytes
            vector = b64decode(vector)
            # Return a tuple of the encrypted text and the IV
            return (encrypted, vector)
            done = True
        # Detect known error if the file is not found
        except (binascii.Error, IndexError) as e:
            print("\"" + filename + "\" has wrong formatting. Try again.")
        except FileNotFoundError:
            print("Can't find \"" + filename + "\". Please try again.")


# Modelled after PKCS7 and figures out its own padding character
def _unPadMessage(msg: str):
    # get the last character and use it as the amount to unpad
    padlength = msg[-1]
    # Convert this into a useable integer
    padlength = int(padlength)
    # Reduce the length of the message by the pad length
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
    # status boolean so that excepttions cause repeat of while loop
    done = False
    while not done:
        try:
            # Create a key
            key = _createKey()
            # Read the encrypted message and IV from the nominated file
            cipherdata = _readCryptoFile()
            # Seperate out the returned Tuple into the encrypted message and IV
            ciphertext = cipherdata[0]
            vector = cipherdata[1]
            # Attempt the decryption with the given values
            decrypted = _decrypt(ciphertext, key, vector)
            # Print the decrypted message in a PGP-inspired way
            print("\n-----BEGIN DECRYPTED MESSAGE-----\n")
            print(decrypted)
            print("\n-----END DECRYPTED MESSAGE------\n")
            done = True
        # Detect known error if any of the decryption values are incorrect
        except ValueError:
            keyStr = key.decode()
            print("Key \"" + keyStr + "\" is incorrect. Please try again.")
    input("Done. Press ENTER to exit.")


try:
    print("CSI2108 AES256-CBC SYMMETRIC ENCRYPTION TOOL")
    choice = "0"
    while (choice != "1") and (choice != "2"):
        choice = input("Please enter 1 to encrypt or 2 to decrypt a file: ")
    if (choice == "1"):
        _encryptWrapper()
    if (choice == "2"):
        _decryptWrapper()
except KeyboardInterrupt:
    # Catch keyboard interrupts and close cleanl rather than crashing
    quit()
