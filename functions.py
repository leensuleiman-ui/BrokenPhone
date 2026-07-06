# -*- coding: utf-8 -*-
"""
functions.py
"""

import socket
import random
import struct
import Mysetting as settings
from logger import Logger

log = Logger(name="FUNCTIONS")

def get_free_tcp_port(start: int = settings.TCP_PORT_RANGE_START, end: int = settings.TCP_PORT_RANGE_END) -> int:
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("", port))
                return port
            except OSError:
                continue
    raise RuntimeError("לא נמצא פורט TCP פנוי בטווח שהוגדר")

def ip_to_bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str)

def bytes_to_ip(ip_bytes: bytes) -> str:
    return socket.inet_ntoa(ip_bytes)

def _signature_bytes() -> bytes:
    sig = settings.SIGNATURE.encode(settings.ENCODING)
    return sig.ljust(settings.SIGNATURE_SIZE, b"\x00")

def build_request(rand_num: int) -> bytes:
    """בניית הודעת Request עם מספר אקראי שנקבע מבחוץ (לצורך מעקב)"""
    sig = _signature_bytes()
    rand_bytes = struct.pack("!I", rand_num)
    request = sig + rand_bytes
    assert len(request) == settings.REQUEST_SIZE, "גודל הודעת Request שגוי"
    return request

def build_offer(random_number: int, tcp_port: int, ip_address: str) -> bytes:
    sig = _signature_bytes()
    rand_bytes = struct.pack("!I", random_number)
    ip_bytes = ip_to_bytes(ip_address)
    port_bytes = struct.pack("!H", tcp_port)

    offer = sig + rand_bytes + ip_bytes + port_bytes
    assert len(offer) == settings.OFFER_SIZE, "גודל הודעת Offer שגוי"
    return offer

def extract_request(data: bytes) -> dict:
    if len(data) != settings.REQUEST_SIZE:
        raise ValueError(f"גודל הודעת Request שגוי: {len(data)} בתים")
    sig = data[:settings.SIGNATURE_SIZE].rstrip(b"\x00").decode(settings.ENCODING)
    rand_num = struct.unpack("!I", data[settings.SIGNATURE_SIZE:settings.SIGNATURE_SIZE + 4])[0]
    if sig != settings.SIGNATURE:
        raise ValueError("חתימה לא תקינה בהודעת Request")
    return {"signature": sig, "random_number": rand_num}

def extract_offer(data: bytes) -> dict:
    if len(data) != settings.OFFER_SIZE:
        raise ValueError(f"גודל הודעת Offer שגוי: {len(data)} בתים")
    offset = settings.SIGNATURE_SIZE
    sig = data[:offset].rstrip(b"\x00").decode(settings.ENCODING)
    rand_num = struct.unpack("!I", data[offset:offset + 4])[0]
    offset += 4
    ip_address = bytes_to_ip(data[offset:offset + 4])
    offset += 4
    tcp_port = struct.unpack("!H", data[offset:offset + 2])[0]
    if sig != settings.SIGNATURE:
        raise ValueError("חתימה לא תקינה בהודעת Offer")
    return {"signature": sig, "random_number": rand_num, "tcp_port": tcp_port, "ip_address": ip_address}

def put_mistake_in_msg(message: str) -> str:
    if len(message) == 0:
        return message
    chars = list(message)
    index_to_change = random.randint(0, len(chars) - 1)
    original_char = chars[index_to_change]
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    new_char = random.choice(alphabet)
    while new_char == original_char:
        new_char = random.choice(alphabet)
    chars[index_to_change] = new_char
    return "".join(chars)

def write_request(direction: str, request_dict: dict):
    print(f"REQUEST {direction}: random_number={request_dict.get('random_number')}")

def write_offer(direction: str, offer_dict: dict):
    print(f"OFFER {direction}: random_number={offer_dict.get('random_number')}, tcp_port={offer_dict.get('tcp_port')}, ip={offer_dict.get('ip_address')}")

def send_msg(conn, data: bytes):
    length_prefix = struct.pack("!I", len(data))
    conn.sendall(length_prefix + data)

def recv_exact(conn, num_bytes: int) -> bytes:
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
    length_prefix = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", length_prefix)
    return recv_exact(conn, length)