# -*- coding: utf-8 -*-
"""
crypto_utils.py
מודול הצפנה (בונוס): RSA ליצירת ערוץ מאובטח והחלפת מפתח AES,
ו-AES-256-CBC עם IV אקראי וייחודי לכל הודעה.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import Mysetting as settings

class CryptoError(Exception):
    """שגיאה מותאמת אישית עבור תהליכי ההצפנה והפענוח של המערכת"""
    pass

def generate_rsa_keypair():
    """יוצר זוג מפתחות RSA (פרטי + ציבורי)"""
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
    """מצפין נתונים עם מפתח ציבורי RSA + OAEP padding."""
    try:
        return public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise CryptoError(f"שגיאה בהצפנת RSA: {e}")

def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """מפענח נתונים עם מפתח פרטי RSA + OAEP padding."""
    try:
        return private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise CryptoError(f"שגיאה בפענוח RSA: {e}")

def generate_aes_key() -> bytes:
    """יוצר מפתח AES-256 אקראי (32 בתים)."""
    return os.urandom(settings.AES_KEY_SIZE)

def aes_encrypt(key: bytes, plaintext: str) -> bytes:
    """מצפין מחרוזת טקסט עם AES-256-CBC ומצרף את ה-IV בהתחלה."""
    try:
        iv = os.urandom(settings.AES_IV_SIZE)
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode(settings.ENCODING)) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext
    except Exception as e:
        raise CryptoError(f"שגיאה בהצפנת AES: {e}")

def aes_decrypt(key: bytes, data: bytes) -> str:
    """מפענח הודעה ומצפה לפורמט של IV + Ciphertext."""
    if len(data) < settings.AES_IV_SIZE:
        raise CryptoError("נתונים מוצפנים קצרים מדי - חסר IV")

    try:
        iv = data[:settings.AES_IV_SIZE]
        ciphertext = data[settings.AES_IV_SIZE:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext_bytes = unpadder.update(padded_data) + unpadder.finalize()

        return plaintext_bytes.decode(settings.ENCODING)
    except Exception as e:
        raise CryptoError(f"שגיאה בפענוח AES: {e}")