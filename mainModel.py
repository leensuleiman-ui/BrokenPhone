# -*- coding: utf-8 -*-
"""
mainModel.py
נקודת הכניסה הראשית של תוכנית "טלפון שבור".
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
        self.client_model = None

        # מצבי רשת פעילים
        self.rx_on = False
        self.tx_on = False

        # משתני שמות תצוגה לפי הדרישות בעמוד 3
        self.own_node_name = settings.SIGNATURE
        self.connected_server_name = "None"
        self.connected_client_name = "None"

        self.rx_aes_key = None
        self.tx_aes_key = None
        self._stop_event = threading.Event()
        self.pending_start_message = None

    def display_status(self):
        """דרישה מעמוד 3: הדפסת סטטוס הישויות המחוברות בכל שינוי במצב התוכנית"""
        server_disp = self.connected_server_name if self.tx_on else "None"
        client_disp = self.connected_client_name if self.rx_on else "None"
        print("\n" + "=" * 50)
        print(f" Own Node Name:      {self.own_node_name}")
        print(f" Connected Server:   {server_disp}")
        print(f" Connected Client:   {client_disp}")
        print("=" * 50 + "\n")

    def rx_worker(self):
        self.server_model.start_listening()

        while not self._stop_event.is_set():
            conn = None

            while not self._stop_event.is_set() and conn is None:
                conn, addr = self.server_model.accept_connection()
                if conn is not None:
                    break

                # תיקון קריטי: אם אנחנו פותחי המשחק ועדיין לא התחברנו למישהו שיקבל מאיתנו (Tx),
                # נמנע מלענות לבקשות UDP של אחרים כדי שלא נהפוך לשרת שלהם בטעות ובאופן הפוך.
                if self.pending_start_message is not None and not self.tx_on:
                    time.sleep(0.5)
                    continue

                self.udp.listen_for_request_and_offer(self.own_ip, timeout=settings.SOCKET_TIMEOUT)

            if self._stop_event.is_set():
                return

            try:
                self.rx_aes_key = self.server_model.perform_handshake(conn)
                self.connected_client_name = "Connected_Client_Node"
            except (ConnectionError, OSError, crypto_utils.CryptoError) as e:
                log.error(f"Handshake בצד ה-Rx נכשל: {e}")
                if conn: conn.close()
                self.rx_on = False
                self.connected_client_name = "None"
                continue

            self.rx_on = True
            log.info("מצב Rx: ON")
            self.display_status()

            while not self._stop_event.is_set():
                try:
                    message = self.server_model.receive_message(conn, self.rx_aes_key)
                except (ConnectionError, OSError, crypto_utils.CryptoError) as e:
                    log.error(f"החיבור נסגר או הודעה פגומה: {e}")
                    break

                # דרישה מעמוד 2: אם אנחנו בסוף השרשרת (אין לנו שרת Tx מחובר) - רק מדפיסים למסך
                if not self.tx_on:
                    print(f"\n[*] הודעה הגיעה לסוף שרשרת הטלפון השבור: {message}\n")
                    continue

                log.log_character_modified()
                modified_message = functions.put_mistake_in_msg(message)

                log.log_message_encrypted_again()
                self._forward_message(modified_message)

            if conn: conn.close()
            self.rx_on = False
            self.connected_client_name = "None"
            self.display_status()

    def tx_worker(self):
        while not self._stop_event.is_set():
            # דרישה מעמוד 2: הלקוח מפסיק לחפש שרתים ברגע שמישהו כבר התחבר אלינו כשרת (rx-on-tx-off)
            if self.rx_on and not self.tx_on:
                time.sleep(0.5)
                continue

            offer = None
            while not self._stop_event.is_set() and offer is None:
                if self.rx_on and not self.tx_on:
                    break
                offer = self.udp.send_request_and_wait_offer(timeout=settings.SOCKET_TIMEOUT)

            if self._stop_event.is_set() or offer is None:
                continue

            self.client_model = ClientModel(
                target_ip=offer["ip_address"],
                target_port=offer["tcp_port"],
                logger=Logger(name="TX"),
            )

            if not self.client_model.connect():
                log.error("ההתחברות לשרת נכשלה, ננסה לחפש שרת אחר ברשת...")
                self.tx_on = False
                continue

            try:
                self.tx_aes_key = self.client_model.perform_handshake()
                self.connected_server_name = offer["signature"]
            except (ConnectionError, OSError, crypto_utils.CryptoError) as e:
                log.error(f"Handshake בצד ה-Tx נכשל: {e}")
                self.client_model.close()
                self.tx_on = False
                self.connected_server_name = "None"
                continue

            self.tx_on = True
            log.info("מצב Tx: ON")
            self.display_status()

            if self.pending_start_message is not None:
                self._forward_message(self.pending_start_message)
                self.pending_start_message = None
            return

    def _forward_message(self, message: str):
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
            self.connected_server_name = "None"
            self.display_status()

    def start(self, start_message: str = None):
        self.pending_start_message = start_message

        rx_thread = threading.Thread(target=self.rx_worker, daemon=True)
        tx_thread = threading.Thread(target=self.tx_worker, daemon=True)

        rx_thread.start()
        tx_thread.start()

        log.info(f"הצומת רץ על IP={self.own_ip}, TCP port={self.own_tcp_port}")
        self.display_status()

        try:
            while not self._stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("עצירת התוכנית...")
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