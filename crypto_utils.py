# -*- coding: utf-8 -*-
"""
crypto_utils.py
מודול הצפנה (בונוס): RSA ליצירת ערוץ מאובטח והחלפת מפתח AES,
ו-AES-256-CBC עם IV אקראי וייחודי לכל הודעה, להצפנת כל הודעות ה-TCP.

משתמש בספריית cryptography (hazmat) כפי שהותר בדרישה 8.
"""

import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

import Mysetting as settings


# ---------------------------------------------------------------------------
# RSA - יצירת זוג מפתחות, סריאליזציה, הצפנה/פענוח של מפתח AES
# ---------------------------------------------------------------------------
def generate_rsa_keypair():
    """יוצר זוג מפתחות RSA (פרטי + ציבורי) בגודל שהוגדר ב-Mysetting."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=settings.RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> bytes:
    """הופך מפתח ציבורי לבתים (PEM) לשליחה ברשת."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_data: bytes):
    """הופך בתים (PEM) חזרה למפתח ציבורי."""
    return serialization.load_pem_public_key(pem_data)


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """מצפין נתונים (בד"כ מפתח AES) עם מפתח ציבורי RSA + OAEP padding."""
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """מפענח נתונים (מפתח AES מוצפן) עם מפתח פרטי RSA + OAEP padding."""
    return private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# AES-256-CBC - יצירת מפתח, הצפנה ופענוח עם IV אקראי לכל הודעה
# ---------------------------------------------------------------------------
def generate_aes_key() -> bytes:
    """יוצר מפתח AES-256 אקראי (32 בתים)."""
    return os.urandom(settings.AES_KEY_SIZE)


def aes_encrypt(key: bytes, plaintext: str) -> bytes:
    """
    מצפין מחרוזת טקסט עם AES-256-CBC.
    יוצר IV אקראי וחדש עבור כל קריאה, ומצרף אותו בתחילת ההודעה המוצפנת
    (IV + ciphertext) כדי שהצד השני יוכל לפענח.
    """
    iv = os.urandom(settings.AES_IV_SIZE)

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode(settings.ENCODING)) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


def aes_decrypt(key: bytes, data: bytes) -> str:
    """
    מפענח הודעה שהוצפנה על ידי aes_encrypt.
    מצפה שהפורמט יהיה IV (16 בתים ראשונים) + ciphertext.
    """
    if len(data) < settings.AES_IV_SIZE:
        raise ValueError("נתונים מוצפנים קצרים מדי - חסר IV")

    iv = data[:settings.AES_IV_SIZE]
    ciphertext = data[settings.AES_IV_SIZE:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext_bytes = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext_bytes.decode(settings.ENCODING)