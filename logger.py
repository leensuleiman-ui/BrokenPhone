# -*- coding: utf-8 -*-
"""
logger.py
מודול לוגר משותף למערכת. כותב אירועים לקובץ brokenPhone.log
ומדפיס ללקוח את הפלטים (הצעות/בקשות) בלבד, כפי שנדרש במטלה.

שימו לב (לפי ההנחיה): יש להוסיף למערכת Logger שיציג את שלבי ההצפנה בלבד,
ולא להדפיס את המפתחות עצמם.
"""

import threading
from datetime import datetime

import Mysetting as settings


class Logger:
    """
    Logger בסיסי, thread-safe, הכותב לקובץ log ומאפשר גם הדפסה למסך.
    ניתן ליצור מופע אחד משותף (singleton-like) או מופע per-module עם prefix.
    """

    _lock = threading.Lock()

    def __init__(self, name: str = "MAIN", log_file: str = settings.LOG_FILE_NAME):
        self.name = name
        self.log_file = log_file

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _write(self, level: str, message: str):
        line = f"[{self._timestamp()}] [{level}] [{self.name}] {message}"
        with Logger._lock:
            try:
                with open(self.log_file, "a", encoding=settings.ENCODING) as f:
                    f.write(line + "\n")
            except OSError as e:
                print(f"שגיאה בכתיבה לקובץ הלוג: {e}")

    # ---------- API כללי ----------
    def info(self, message: str):
        self._write("INFO", message)

    def warning(self, message: str):
        self._write("WARNING", message)

    def error(self, message: str):
        self._write("ERROR", message)

    def debug(self, message: str):
        self._write("DEBUG", message)

    # ---------- הדפסות ייעודיות שנדרשות במטלה ----------
    def print_and_log(self, message: str):
        """מדפיס למסך וגם כותב ללוג - למשל בקשות/הצעות שהתקבלו/נשלחו."""
        print(message)
        self._write("INFO", message)

    # ---------- אירועי הצפנה (בונוס) - לפי הדוגמה מהמסמך ----------
    def log_rsa_keypair_generated(self):
        self.print_and_log("RSA key pair generated")

    def log_public_key_sent(self):
        self.print_and_log("Public key sent")

    def log_aes_session_key_generated(self):
        self.print_and_log("AES session key generated")

    def log_aes_key_encrypted(self):
        self.print_and_log("AES key encrypted using RSA")

    def log_encrypted_aes_key_received(self):
        self.print_and_log("Encrypted AES key received")

    def log_aes_key_decrypted(self):
        self.print_and_log("AES key decrypted successfully")

    def log_message_encrypted(self):
        self.print_and_log("Message encrypted (AES)")

    def log_message_decrypted(self):
        self.print_and_log("Message decrypted")

    def log_character_modified(self):
        self.print_and_log("Character modified")

    def log_message_encrypted_again(self):
        self.print_and_log("Message encrypted again")

    def log_message_sent(self):
        self.print_and_log("Message sent")