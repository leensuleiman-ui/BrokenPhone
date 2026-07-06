# -*- coding: utf-8 -*-
"""
mainModel.py
נקודת הכניסה הראשית של תוכנית "טלפון שבור".

מריץ שני תהליכונים (threads) במקביל:
  1. rx_thread   - מטפל בצד ה-Rx: מפרסם את עצמו (Offer) בתגובה ל-Request,
                   מקבל חיבור TCP, מבצע handshake כשרת, ולאחר מכן מקבל
                   הודעות מוצפנות, משנה תו אקראי, ומעביר ל-Tx.
  2. tx_thread   - מטפל בצד ה-Tx: משדר Request עד שמתקבל Offer, מתחבר
                   ל-TCP של השרת שנמצא, ומבצע handshake כלקוח.

לאחר שהחיבורים בשני הצדדים מוכנים (rx_on_tx_on), התוכנית עוברת ללולאת
העברת ההודעות (broken phone loop): קבלה -> פענוח -> שינוי תו -> הצפנה -> שליחה.

הערה: אם רוצים להתחיל את המשחק (המדול הראשון בשרשרת), יש להזין הודעת
פתיחה מהקונסולה - זו תישלח ברגע שחיבור ה-Tx יהיה מוכן.
"""

import threading
import time

import Mysetting as settings
import functions
import crypto_utils
from logger import Logger
from UDPDiscovery import UDPDiscovery, get_local_ip
from ServerModel import ServerModel
from ClientModel import ClientModel

log = Logger(name="MAIN")


class BrokenPhoneNode:
    def __init__(self):
        self.own_ip = get_local_ip()
        self.own_tcp_port = functions.get_free_tcp_port()
        self.udp = UDPDiscovery(own_tcp_port=self.own_tcp_port)

        self.server_model = ServerModel(self.own_tcp_port, logger=Logger(name="RX"))
        self.client_model = None  # ייווצר אחרי שנמצא שרת יעד

        # מצבים (state machine)
        self.rx_on = False
        self.tx_on = False

        # מפתחות AES לכל צד (נפרדים - כל חיבור עם handshake משלו)
        self.rx_aes_key = None
        self.tx_aes_key = None

        self._stop_event = threading.Event()

        # הודעת פתיחה אופציונלית (אם המודול הזה פותח את המשחק)
        self.pending_start_message = None

    # -----------------------------------------------------------------
    # RX THREAD - מציע את עצמו כ-Rx פנוי, מקבל חיבור, ואז מאזין להודעות
    # -----------------------------------------------------------------
    def rx_worker(self):
        """
        לולאה חיצונית שרצה עד לעצירת התוכנית: בכל כשל (handshake פגום,
        חיבור שנסגר, הודעה מוצפנת לא תקינה וכו') - נסגר החיבור, מוצגת
        שגיאה מתאימה, המצב חוזר ל-rx_off, והתוכנית חוזרת להמתין לחיבור
        חדש במקום לקרוס (דרישה 7).
        """
        self.server_model.start_listening()

        while not self._stop_event.is_set():
            conn = None

            # שלב 1: כל עוד אין חיבור, נענה על Request עם Offer ובמקביל ננסה accept
            while not self._stop_event.is_set() and conn is None:
                conn, addr = self.server_model.accept_connection()
                if conn is not None:
                    break
                self.udp.listen_for_request_and_offer(self.own_ip, timeout=settings.SOCKET_TIMEOUT)

            if self._stop_event.is_set():
                return

            # שלב 2: handshake כשרת
            try:
                self.rx_aes_key = self.server_model.perform_handshake(conn)
            except (ConnectionError, OSError, crypto_utils.CryptoError) as e:
                log.error(f"Handshake בצד ה-Rx נכשל, מחזירים את המצב ל-rx_off: {e}")
                conn.close()
                self.rx_on = False
                continue  # חוזרים להמתין לחיבור חדש

            self.rx_on = True
            log.info("מצב Rx: ON")

            # שלב 3: לולאת קבלת הודעות והעברתן הלאה (broken phone)
            while not self._stop_event.is_set():
                try:
                    message = self.server_model.receive_message(conn, self.rx_aes_key)
                except (ConnectionError, OSError, crypto_utils.CryptoError) as e:
                    log.error(f"החיבור נסגר / הודעה לא תקינה, מחזירים את המצב ל-rx_off: {e}")
                    break

                log.log_character_modified()
                modified_message = functions.put_mistake_in_msg(message)
                self._forward_message(modified_message)

            conn.close()
            self.rx_on = False

    # -----------------------------------------------------------------
    # TX THREAD - מחפש שרת יעד (Request/Offer), מתחבר אליו כ-Tx
    # -----------------------------------------------------------------
    def tx_worker(self):
        """
        לולאה חיצונית: אם ה-handshake נכשל, או שהחיבור לשרת שגוי/פגום,
        התוכנית לא קורסת - המצב חוזר ל-tx_off והיא חוזרת לחפש שרת יעד
        אחר באמצעות Request/Offer מחדש (דרישה 7).
        """
        while not self._stop_event.is_set():
            offer = None
            while not self._stop_event.is_set() and offer is None:
                offer = self.udp.send_request_and_wait_offer(timeout=settings.SOCKET_TIMEOUT)

            if self._stop_event.is_set() or offer is None:
                return

            self.client_model = ClientModel(
                target_ip=offer["ip_address"],
                target_port=offer["tcp_port"],
                logger=Logger(name="TX"),
            )

            if not self.client_model.connect():
                log.error("לא הצלחנו להתחבר לשרת היעד לאחר קבלת Offer, מחפשים שרת אחר")
                self.tx_on = False
                continue

            try:
                self.tx_aes_key = self.client_model.perform_handshake()
            except (ConnectionError, OSError, crypto_utils.CryptoError) as e:
                log.error(f"Handshake בצד ה-Tx נכשל, מחזירים את המצב ל-tx_off: {e}")
                self.client_model.close()
                self.tx_on = False
                continue

            self.tx_on = True
            log.info("מצב Tx: ON")

            # אם יש הודעת פתיחה ממתינה (המודול הזה פתח את המשחק) - שולחים עכשיו
            if self.pending_start_message is not None:
                self._forward_message(self.pending_start_message)
                self.pending_start_message = None

            return  # חיבור Tx יציב הוקם - מסיימים את הלולאה

    # -----------------------------------------------------------------
    def _forward_message(self, message: str):
        """שולח הודעה דרך ה-Tx, אם הוא כבר מוכן. אחרת ממתין בקצרה."""
        wait_start = time.time()
        while not self.tx_on and time.time() - wait_start < settings.TX_WAIT_TIMEOUT:
            time.sleep(0.2)

        if not self.tx_on or self.client_model is None:
            log.error("אין חיבור Tx פעיל - לא ניתן להעביר את ההודעה")
            return

        try:
            self.client_model.send_message(self.tx_aes_key, message)
        except (OSError, crypto_utils.CryptoError) as e:
            log.error(f"שגיאה בשליחת הודעה דרך Tx: {e}")
            self.tx_on = False

    # -----------------------------------------------------------------
    def start(self, start_message: str = None):
        """
        מפעיל את שני התהליכונים (Rx/Tx).
        אם start_message ניתן - הודעה זו תישלח ברגע שחיבור ה-Tx יהיה מוכן
        (כלומר המודול הזה פותח את סבב המשחק).
        """
        self.pending_start_message = start_message

        rx_thread = threading.Thread(target=self.rx_worker, daemon=True)
        tx_thread = threading.Thread(target=self.tx_worker, daemon=True)

        rx_thread.start()
        tx_thread.start()

        log.info(f"הצומת רץ על IP={self.own_ip}, TCP port={self.own_tcp_port}")

        try:
            while not self._stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("עצירת התוכנית לפי בקשת המשתמש")
            self._stop_event.set()
            if self.client_model:
                self.client_model.close()
            self.server_model.close()


if __name__ == "__main__":
    node = BrokenPhoneNode()

    answer = input("האם צומת זה פותח את סבב המשחק? (y/n): ").strip().lower()
    initial_msg = None
    if answer == "y":
        initial_msg = input("הזן/י את הודעת הפתיחה: ")

    node.start(start_message=initial_msg)