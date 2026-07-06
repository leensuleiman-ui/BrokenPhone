# -*- coding: utf-8 -*-
"""
UDPDiscovery.py
מטפל בסינון הודעות עצמיות ומניעת לולאה אינסופית על אותו מחשב.
"""

import socket
import random
import threading
import Mysetting as settings
import functions
from logger import Logger

log = Logger(name="UDP")


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


class UDPDiscovery:
    def __init__(self, own_tcp_port: int, udp_port: int = settings.UDP_DISCOVERY_PORT):
        self.own_tcp_port = own_tcp_port
        self.udp_port = udp_port

        # מחסן מספרים אקראיים למניעת מענה לעצמנו
        self.sent_rand_nums = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------
    # Client Side (TX)
    # ------------------------------------------------------------
    def send_request_and_wait_offer(self, timeout: float = settings.SOCKET_TIMEOUT):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(timeout)

            try:
                sock.bind(("0.0.0.0", self.udp_port))
            except OSError:
                pass

            # הגרלת מספר אקראי ושמירתו במחסן הפנימי של הצומת הזה
            rand_num = random.randint(1, 2 ** 32 - 1)
            with self._lock:
                self.sent_rand_nums.add(rand_num)

            request_msg = functions.build_request(rand_num)
            request_info = functions.extract_request(request_msg)

            try:
                sock.sendto(request_msg, (settings.UDP_BROADCAST_ADDR, self.udp_port))
                functions.write_request("SENT", request_info)
            except OSError as e:
                log.error(f"שגיאה בשליחת Request: {e}")
                return None

            while True:
                try:
                    data, addr = sock.recvfrom(settings.UDP_BUFFER_SIZE)
                    if len(data) == settings.OFFER_SIZE:
                        offer_info = functions.extract_offer(data)
                        # וידוא שההצעה היא תגובה ישירה לבקשה שלנו
                        if offer_info["random_number"] == rand_num:
                            functions.write_offer("RECEIVED", offer_info)
                            return offer_info
                except socket.timeout:
                    return None
                except Exception as e:
                    log.error(f"שגיאה בקבלת Offer: {e}")
                    return None

    # ------------------------------------------------------------
    # Server Side (RX)
    # ------------------------------------------------------------
    def listen_for_request_and_offer(self, own_ip: str, timeout: float = settings.SOCKET_TIMEOUT):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.settimeout(timeout)

            try:
                sock.bind(("0.0.0.0", self.udp_port))
                data, addr = sock.recvfrom(settings.UDP_BUFFER_SIZE)

                if len(data) == settings.REQUEST_SIZE:
                    req_info = functions.extract_request(data)

                    # מנגנון קסם: אם מספר הבקשה יוצר על ידינו - אנחנו מתעלמים מיד ולא עונים!
                    with self._lock:
                        if req_info["random_number"] in self.sent_rand_nums:
                            return

                    functions.write_request("RECEIVED", req_info)

                    # בניית מענה (Offer) עם הנתונים שלנו
                    offer_msg = functions.build_offer(
                        random_number=req_info["random_number"],
                        tcp_port=self.own_tcp_port,
                        ip_address=own_ip
                    )

                    sock.sendto(offer_msg, (addr[0], self.udp_port))
                    offer_info = functions.extract_offer(offer_msg)
                    functions.write_offer("SENT", offer_info)

            except socket.timeout:
                pass
            except Exception as e:
                log.error(f"שגיאה בשרת ה-UDP: {e}")