# -*- coding: utf-8 -*-
"""
ServerModel.py
מייצג את צד ה-Rx (השרת): מאזין לחיבורי TCP מלקוחות שמתחברים אליו,
מבצע handshake (כשרת) ליצירת ערוץ מוצפן, ומקבל הודעות מוצפנות.
"""

import socket

import Mysetting as settings
import functions
import crypto_utils
from logger import Logger


class ServerModel:
    def __init__(self, tcp_port: int, logger: Logger = None):
        self.tcp_port = tcp_port
        self.log = logger or Logger(name="SERVER")
        self.listen_socket = None
        self.private_key = None
        self.public_key = None

    # -----------------------------------------------------------------
    def start_listening(self):
        """פותח socket האזנה על הפורט שהוקצה."""
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind(("", self.tcp_port))
        self.listen_socket.listen(1)
        self.listen_socket.settimeout(settings.SOCKET_TIMEOUT)
        self.log.info(f"השרת מאזין על פורט {self.tcp_port}")

    def accept_connection(self):
        """
        מנסה לקבל חיבור נכנס אחד (עם טיימאאוט).
        מחזיר (conn, addr) אם התקבל חיבור, אחרת (None, None).
        """
        try:
            conn, addr = self.listen_socket.accept()
            self.log.info(f"התקבל חיבור TCP מ- {addr}")
            return conn, addr
        except socket.timeout:
            return None, None
        except OSError as e:
            self.log.error(f"שגיאה בקבלת חיבור: {e}")
            return None, None

    # -----------------------------------------------------------------
    # handshake - צד השרת יוצר RSA, שולח מפתח ציבורי, מקבל מפתח AES מוצפן
    # -----------------------------------------------------------------
    def perform_handshake(self, conn) -> bytes:
        """
        מבצע את שלב ההחלפה (דרישה 2):
        1. השרת מייצר זוג מפתחות RSA.
        2. השרת שולח ללקוח את המפתח הציבורי בלבד.
        3. הלקוח מייצר מפתח AES אקראי, מצפין אותו עם המפתח הציבורי, ושולח.
        4. השרת מפענח את מפתח ה-AES עם המפתח הפרטי שלו.
        מחזיר את מפתח ה-AES (bytes) לשימוש בהמשך התקשורת.
        """
        self.private_key, self.public_key = crypto_utils.generate_rsa_keypair()
        self.log.log_rsa_keypair_generated()

        public_key_bytes = crypto_utils.serialize_public_key(self.public_key)
        functions.send_msg(conn, public_key_bytes)
        self.log.log_public_key_sent()

        encrypted_aes_key = functions.recv_msg(conn)
        self.log.log_encrypted_aes_key_received()

        try:
            aes_key = crypto_utils.rsa_decrypt(self.private_key, encrypted_aes_key)
        except ValueError as e:
            self.log.error(f"פענוח מפתח AES נכשל - מפתח פגום: {e}")
            raise

        self.log.log_aes_key_decrypted()
        return aes_key

    # -----------------------------------------------------------------
    def receive_message(self, conn, aes_key: bytes) -> str:
        """מקבל הודעה מוצפנת ומפענח אותה עם מפתח ה-AES."""
        encrypted_data = functions.recv_msg(conn)
        try:
            plaintext = crypto_utils.aes_decrypt(aes_key, encrypted_data)
        except ValueError as e:
            self.log.error(f"הודעה מוצפנת שאינה תקינה: {e}")
            raise
        self.log.log_message_decrypted()
        return plaintext

    def close(self):
        if self.listen_socket:
            self.listen_socket.close()
            self.listen_socket = None