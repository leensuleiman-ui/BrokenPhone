# -*- coding: utf-8 -*-
"""
ClientModel.py
מייצג את צד ה-Tx (הלקוח): מתחבר לשרת (IP+PORT) שהתקבל בהצעה (Offer),
מבצע handshake (כלקוח) ליצירת ערוץ מוצפן, ושולח הודעות מוצפנות.
"""

import socket

import Mysetting as settings
import functions
import crypto_utils
from logger import Logger


class ClientModel:
    def __init__(self, target_ip: str, target_port: int, logger: Logger = None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.log = logger or Logger(name="CLIENT")
        self.conn = None

    # -----------------------------------------------------------------
    def connect(self) -> bool:
        """מתחבר לשרת היעד. מחזיר True בהצלחה, False בכישלון."""
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.settimeout(settings.SOCKET_TIMEOUT)
            self.conn.connect((self.target_ip, self.target_port))
            self.log.info(f"התחברנו לשרת {self.target_ip}:{self.target_port}")
            return True
        except OSError as e:
            self.log.error(f"התחברות לשרת {self.target_ip}:{self.target_port} נכשלה: {e}")
            self.conn = None
            return False

    # -----------------------------------------------------------------
    # handshake - צד הלקוח מקבל מפתח ציבורי, מייצר AES, מצפין ושולח
    # -----------------------------------------------------------------
    def perform_handshake(self) -> bytes:
        """
        מבצע את שלב ההחלפה (דרישה 2) מצד הלקוח:
        1. מקבל מהשרת את המפתח הציבורי RSA.
        2. מייצר מפתח AES-256 אקראי.
        3. מצפין את מפתח ה-AES עם המפתח הציבורי של השרת.
        4. שולח את מפתח ה-AES המוצפן לשרת.
        מחזיר את מפתח ה-AES (bytes) לשימוש בהמשך התקשורת.
        """
        public_key_bytes = functions.recv_msg(self.conn)
        public_key = crypto_utils.deserialize_public_key(public_key_bytes)

        aes_key = crypto_utils.generate_aes_key()
        self.log.log_aes_session_key_generated()

        encrypted_aes_key = crypto_utils.rsa_encrypt(public_key, aes_key)
        self.log.log_aes_key_encrypted()

        functions.send_msg(self.conn, encrypted_aes_key)
        return aes_key

    # -----------------------------------------------------------------
    def send_message(self, aes_key: bytes, plaintext: str):
        """מצפין הודעה עם מפתח ה-AES ושולח אותה לשרת."""
        encrypted_data = crypto_utils.aes_encrypt(aes_key, plaintext)
        self.log.log_message_encrypted()
        functions.send_msg(self.conn, encrypted_data)
        self.log.log_message_sent()

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None