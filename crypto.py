import os

from cryptography import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_ITERATIONS=6000
KEY_SIZE=32 # 32x8=256 pt aes-256
NONCE_SIZE=12 #12x8=96

def generate_salt(size=16):
    return os.urandom(size)

def generate_key_from_password(password_bytes, salt):
    kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=KEY_SIZE,salt=salt,iterations=KDF_ITERATIONS,backend=default_backend())
    return kdf.derive(password_bytes)

def generate_new_dek():
    return AESGCM.generate_key(bit_length=256)

def encrypt_data(key,data_bytes):
    aesgcm=AESGCM(key)
    nonce=os.urandom(NONCE_SIZE)
    encrypted_data=aesgcm.encrypt(nonce,data_bytes,None)
    return nonce+encrypted_data

def decrypt_data(key,encrypted_data_with_nonce):
    aesgcm=AESGCM(key)
    nonce=encrypted_data_with_nonce[:NONCE_SIZE]
    encrypted_data=encrypted_data_with_nonce[NONCE_SIZE:]
    return aesgcm.decrypt(nonce,encrypted_data,None)
