import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# Encrypted PKCS#8 with scrypt key derivation and authenticated AES-256-GCM.
PRIVATE_KEY_PROTECTION = 'scryptAndAES256-GCM'


def generate_random_key(bits=256):
    """
    Generate a random encryption key. Sizes is given in bits and must be in increments of 32.
    """
    if bits % 32:
        raise Exception(f"Invalid key size ({bits}). Key sizes must be in increments of 32 bits.")
    return os.urandom(int(bits / 8))


def encrypt_master_key(master_key, public_key):
    """
    Encrypt a secret key with the provided public RSA key.
    """
    key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(master_key)


def decrypt_master_key(master_key_cipher, private_key):
    """
    Decrypt a secret key with the provided private RSA key.
    """
    key = RSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(master_key_cipher)


def lock_private_key(private_key, master_password, scrypt_n):
    """
    Encrypt an RSA private key with a master password.

    Returns the key as an encrypted PKCS#8 PEM string (scrypt + AES-256-GCM).
    """
    if not master_password:
        raise ValueError("A master password is required.")
    key = RSA.import_key(private_key)
    if not key.has_private():
        raise ValueError("The provided key is not a private key.")
    return key.export_key(
        format='PEM',
        pkcs=8,
        passphrase=master_password,
        protection=PRIVATE_KEY_PROTECTION,
        prot_params={'iteration_count': scrypt_n},
    ).decode('utf-8')


def unlock_private_key(encrypted_private_key, master_password):
    """
    Decrypt an encrypted PKCS#8 private key with a master password.

    Returns the private key as an unencrypted PEM string, or None if the password is wrong.
    """
    if not encrypted_private_key or not master_password:
        return None
    try:
        key = RSA.import_key(encrypted_private_key, passphrase=master_password)
    except (ValueError, IndexError, TypeError):
        return None
    if not key.has_private():
        return None
    return key.export_key(format='PEM').decode('utf-8')


def private_key_matches(private_key, public_key):
    """
    Return True if the private key belongs to the given public key.
    """
    try:
        private = RSA.import_key(private_key)
        public = RSA.import_key(public_key)
    except (ValueError, IndexError, TypeError):
        return False
    if not private.has_private():
        return False
    return private.n == public.n and private.e == public.e
