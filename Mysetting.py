# -*- coding: utf-8 -*-
"""
Mysetting.py
קובץ הגדרות גלובלי ומשתנים משותפים לכל המערכת (Broken Phone Project).
"""

# ---------- הגדרות UDP ----------
UDP_DISCOVERY_PORT = 6000          # הפורט הקבוע לשידור/קליטת broadcast של UDP
UDP_BROADCAST_ADDR = "255.255.255.255"
UDP_BUFFER_SIZE = 1024

# ---------- הגדרות TCP ----------
TCP_PORT_RANGE_START = 6001
TCP_PORT_RANGE_END = 7000
TCP_BUFFER_SIZE = 4096              # גודל buffer לחיבורי TCP

# ---------- מבנה הודעות (לפי הדרישות) ----------
SIGNATURE = "Networking17"          # החתימה שחייבת להופיע ב-16 בתים הראשונים
SIGNATURE_SIZE = 16                 # גודל שדה החתימה בבתים
RANDOM_NUM_SIZE = 4                 # 32 ביט = 4 בתים
PORT_FIELD_SIZE = 2                 # 16 ביט לפורט
IP_FIELD_SIZE = 4                   # 32 ביט לכתובת IP

REQUEST_SIZE = SIGNATURE_SIZE + RANDOM_NUM_SIZE                      # 20 בתים
OFFER_SIZE = SIGNATURE_SIZE + RANDOM_NUM_SIZE + PORT_FIELD_SIZE + IP_FIELD_SIZE  # 26 בתים

# ---------- הגדרות זמן (טיימאאוטים) ----------
SOCKET_TIMEOUT = 2.0                # שניות - טיימאאוט ל-recvfrom/accept
UDP_BROADCAST_INTERVAL = 1.0        # תדירות שליחת request/offer בעת המתנה
TX_WAIT_TIMEOUT = 30                # זמן המתנה מקסימלי לחיבור Tx לפני ויתור

# ---------- הגדרות מצב (Rx/Tx) ----------
RX_OFF = "rx_off"
RX_ON = "rx_on"
TX_OFF = "tx_off"
TX_ON = "tx_on"

# ---------- קידוד ----------
ENCODING = "utf-8"

# ---------- קובץ לוג ----------
LOG_FILE_NAME = "brokenPhone.log"

# ---------- הגדרות הצפנה (בונוס) ----------
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32   # 256 ביט
AES_IV_SIZE = 16     # גודל בלוק AES