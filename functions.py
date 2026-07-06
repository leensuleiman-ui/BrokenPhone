# -*- coding: utf-8 -*-
"""
functions.py
אוסף פעולות נדרשות: איתור פורט TCP פנוי, המרות IP<->bytes, בניית/פירוק
הודעות Request ו-Offer, הכנסת טעות אקראית להודעה, וכתיבת לוגים ייעודיים.
"""

import socket
import random
import struct

import Mysetting as settings
from logger import Logger

log = Logger(name="FUNCTIONS")


# ---------------------------------------------------------------------------
# get_free_tcp_port - מציאת פורט פנוי בין 6001 ל-7000
# ---------------------------------------------------------------------------
def get_free_tcp_port(start: int = settings.TCP_PORT_RANGE_START,
                       end: int = settings.TCP_PORT_RANGE_END) -> int:
    """
    מוצא ומחזיר פורט TCP פנוי בטווח [start, end].
    בודק בפועל שהפורט ניתן ל-bind (ולא רק שהוא לא נמצא ברשימה פנימית).
    """
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("", port))
                return port
            except OSError:
                continue
    raise RuntimeError("לא נמצא פורט TCP פנוי בטווח שהוגדר")


# ---------------------------------------------------------------------------
# המרות IP <-> bytes
# ---------------------------------------------------------------------------
def ip_to_bytes(ip_str: str) -> bytes:
    """הופך כתובת IP מחרוזת (למשל '192.168.1.1') ל-4 בתים."""
    return socket.inet_aton(ip_str)


def bytes_to_ip(ip_bytes: bytes) -> str:
    """הופך 4 בתים חזרה למחרוזת IP."""
    return socket.inet_ntoa(ip_bytes)


# ---------------------------------------------------------------------------
# random_with_N_digits - יצירת מספר אקראי בן N ספרות
# ---------------------------------------------------------------------------
def random_with_n_digits(n: int) -> int:
    if n <= 0:
        raise ValueError("n חייב להיות גדול מ-0")
    lower = 10 ** (n - 1)
    upper = (10 ** n) - 1
    return random.randint(lower, upper)


# ---------------------------------------------------------------------------
# בניית הודעות
# ---------------------------------------------------------------------------
def _signature_bytes() -> bytes:
    """מחזיר את החתימה כ-16 בתים בדיוק (padding באפסים אם צריך)."""
    sig = settings.SIGNATURE.encode(settings.ENCODING)
    if len(sig) > settings.SIGNATURE_SIZE:
        raise ValueError("החתימה ארוכה מדי מהגודל המוגדר")
    return sig.ljust(settings.SIGNATURE_SIZE, b"\x00")


def build_request() -> bytes:
    """
    בניית הודעת Request לפי התבנית:
    [16 בתים חתימה][4 בתים מספר אקראי] = 20 בתים בסה"כ.
    """
    sig = _signature_bytes()
    rand_num = random.randint(0, 2 ** 32 - 1)
    rand_bytes = struct.pack("!I", rand_num)  # 4 בתים, Big-Endian
    request = sig + rand_bytes
    assert len(request) == settings.REQUEST_SIZE, "גודל הודעת Request שגוי"
    return request


def build_offer(random_number: int, tcp_port: int, ip_address: str) -> bytes:
    """
    בניית הודעת Offer לפי התבנית:
    [16 בתים חתימה][4 בתים אותו random_number מה-Request]
    [4 בתים IP][2 בתים פורט] = 26 בתים.

    שימו לב: ה-random_number כאן הוא אותו מספר שהתקבל בהודעת ה-Request
    המקורית (ולא מספר חדש), כדי שהצד ששלח את ה-Request יוכל לוודא
    שההצעה שהתקבלה אכן שייכת לבקשה שלו.
    """
    sig = _signature_bytes()
    rand_bytes = struct.pack("!I", random_number)
    ip_bytes = ip_to_bytes(ip_address)         # 4 בתים
    port_bytes = struct.pack("!H", tcp_port)   # 2 בתים

    offer = sig + rand_bytes + ip_bytes + port_bytes
    assert len(offer) == settings.OFFER_SIZE, "גודל הודעת Offer שגוי"
    return offer


# ---------------------------------------------------------------------------
# פירוק הודעות
# ---------------------------------------------------------------------------
def extract_request(data: bytes) -> dict:
    """
    מפרק הודעת Request גולמית למילון עם השדות: signature, random_number.
    מאמת גם את גודל ההודעה ואת תקינות החתימה.
    """
    if len(data) != settings.REQUEST_SIZE:
        raise ValueError(f"גודל הודעת Request שגוי: {len(data)} בתים")

    sig = data[:settings.SIGNATURE_SIZE].rstrip(b"\x00").decode(settings.ENCODING)
    rand_num = struct.unpack("!I", data[settings.SIGNATURE_SIZE:settings.SIGNATURE_SIZE + 4])[0]

    if sig != settings.SIGNATURE:
        raise ValueError("חתימה לא תקינה בהודעת Request")

    return {"signature": sig, "random_number": rand_num}


def extract_offer(data: bytes) -> dict:
    """
    מפרק הודעת Offer גולמית למילון עם השדות:
    signature, random_number, ip_address, tcp_port.
    """
    if len(data) != settings.OFFER_SIZE:
        raise ValueError(f"גודל הודעת Offer שגוי: {len(data)} בתים")

    offset = 0
    sig = data[offset:offset + settings.SIGNATURE_SIZE].rstrip(b"\x00").decode(settings.ENCODING)
    offset += settings.SIGNATURE_SIZE

    rand_num = struct.unpack("!I", data[offset:offset + 4])[0]
    offset += 4

    ip_address = bytes_to_ip(data[offset:offset + 4])
    offset += 4

    tcp_port = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2

    if sig != settings.SIGNATURE:
        raise ValueError("חתימה לא תקינה בהודעת Offer")

    return {
        "signature": sig,
        "random_number": rand_num,
        "tcp_port": tcp_port,
        "ip_address": ip_address,
    }


# ---------------------------------------------------------------------------
# putMistakeInMsg - הכנסת שינוי אקראי (תו אחד) להודעה
# ---------------------------------------------------------------------------
def put_mistake_in_msg(message: str) -> str:
    """
    בוחר תו אחד אקראי בהודעה (כפי שנדרש במעבדה) ומחליף אותו
    באות אנגלית אקראית אחרת. מחזיר את ההודעה החדשה.
    """
    if len(message) == 0:
        return message

    chars = list(message)
    index_to_change = random.randint(0, len(chars) - 1)
    original_char = chars[index_to_change]

    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # לוודא שהתו החדש שונה מהתו המקורי
    new_char = random.choice(alphabet)
    while new_char == original_char:
        new_char = random.choice(alphabet)

    chars[index_to_change] = new_char
    return "".join(chars)


# ---------------------------------------------------------------------------
# כתיבת לוג ייעודית לבקשות/הצעות (console + log file)
# ---------------------------------------------------------------------------
def write_request(direction: str, request_dict: dict):
    """
    direction: 'SENT' או 'RECEIVED'
    מדפיס ורושם ללוג פרטי הודעת Request.
    """
    msg = f"REQUEST {direction}: random_number={request_dict.get('random_number')}"
    log.print_and_log(msg)


def write_offer(direction: str, offer_dict: dict):
    """
    direction: 'SENT' או 'RECEIVED'
    מדפיס ורושם ללוג פרטי הודעת Offer.
    """
    msg = (f"OFFER {direction}: random_number={offer_dict.get('random_number')}, "
           f"tcp_port={offer_dict.get('tcp_port')}, ip={offer_dict.get('ip_address')}")
    log.print_and_log(msg)


# ---------------------------------------------------------------------------
# עזר לשליחה/קבלה של הודעות TCP באורך משתנה (length-prefixed framing)
# ---------------------------------------------------------------------------
def send_msg(conn, data: bytes):
    """
    שולח הודעה בפרוטוקול TCP עם קידומת אורך (4 בתים) לפני התוכן,
    כדי להתמודד עם היות TCP פרוטוקול סטרימינג (ללא הפרדה בין הודעות).
    """
    length_prefix = struct.pack("!I", len(data))
    conn.sendall(length_prefix + data)


def recv_exact(conn, num_bytes: int) -> bytes:
    """מקבל בדיוק num_bytes בתים מהחיבור, או זורק חריגה אם החיבור נסגר."""
    chunks = []
    remaining = num_bytes
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("החיבור נסגר בזמן קבלת נתונים")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_msg(conn) -> bytes:
    """מקבל הודעה שנשלחה עם send_msg (קורא קודם את קידומת האורך)."""
    length_prefix = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", length_prefix)
    return recv_exact(conn, length)