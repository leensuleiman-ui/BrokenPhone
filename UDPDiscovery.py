# -*- coding: utf-8 -*-
"""
UDPDiscovery.py
"""

import socket

import Mysetting as settings
import functions
from logger import Logger

log = Logger(name="UDP")


class UDPDiscovery:

    def __init__(self, own_tcp_port: int,
                 udp_port: int = settings.UDP_DISCOVERY_PORT):

        self.own_tcp_port = own_tcp_port
        self.udp_port = udp_port

    # ------------------------------------------------------------
    # Client Side
    # ------------------------------------------------------------
    def send_request_and_wait_offer(
            self,
            timeout: float = settings.SOCKET_TIMEOUT
    ):

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            sock.settimeout(timeout)

            request_msg = functions.build_request()
            request = functions.extract_request(request_msg)

            try:

                sock.sendto(
                    request_msg,
                    (settings.UDP_BROADCAST_ADDR,
                     self.udp_port)
                )

                functions.write_request("SENT", request)

            except OSError as e:

                log.error(f"שגיאה בשליחת Request: {e}")
                return None

            try:

                data, addr = sock.recvfrom(
                    settings.UDP_BUFFER_SIZE
                )

            except socket.timeout:

                return None

            except OSError as e:

                log.error(f"שגיאה בקבלת Offer: {e}")
                return None

            try:

                offer = functions.extract_offer(data)

                # להתעלם רק מה־Offer של עצמי
                if offer["tcp_port"] == self.own_tcp_port:
                    return None

            except ValueError as e:

                log.warning(f"Offer לא תקין: {e}")
                return None

            if offer["random_number"] != request["random_number"]:

                log.warning(
                    "Offer שייך ל-Request אחר."
                )

                return None

            functions.write_offer("RECEIVED", offer)

            return offer

    # ------------------------------------------------------------
    # Server Side
    # ------------------------------------------------------------
    def listen_for_request_and_offer(
            self,
            own_ip: str,
            timeout: float = settings.SOCKET_TIMEOUT
    ):

        with socket.socket(socket.AF_INET,
                           socket.SOCK_DGRAM) as sock:

            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1
            )

            try:
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_REUSEPORT,
                    1
                )
            except (AttributeError, OSError):
                pass



            sock.settimeout(timeout)

            try:

                sock.bind(("", self.udp_port))

            except OSError as e:

                log.error(
                    f"לא ניתן לפתוח UDP: {e}"
                )

                return False

            try:

                data, addr = sock.recvfrom(
                    settings.UDP_BUFFER_SIZE
                )

            except socket.timeout:

                return False

            except OSError as e:

                log.error(
                    f"שגיאה בקבלת Request: {e}"
                )

                return False

            try:

                request = functions.extract_request(data)

            except ValueError as e:

                log.warning(
                    f"Request לא תקין: {e}"
                )

                return False

            functions.write_request(
                "RECEIVED",
                request
            )

            offer_msg = functions.build_offer(
                request["random_number"],
                self.own_tcp_port,
                own_ip
            )

            try:

                sock.sendto(
                    offer_msg,
                    addr
                )

                functions.write_offer(
                    "SENT",
                    functions.extract_offer(
                        offer_msg
                    )
                )

            except OSError as e:

                log.error(
                    f"שגיאה בשליחת Offer: {e}"
                )

                return False

            return True


def get_local_ip():

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:

        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]

    except OSError:

        ip = "127.0.0.1"

    finally:

        s.close()

    return ip