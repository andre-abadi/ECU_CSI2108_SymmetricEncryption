# CSI2108 Semester 1 2018
# Assessable Workshop - Symmetric Encryption

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()
