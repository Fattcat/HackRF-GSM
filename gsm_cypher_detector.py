#!/usr/bin/env python3
"""
GSM šifrovanie detektor
Číta z grgsm UDP streamu a reportuje šifrovanie každej BTS
"""

import socket
import struct
from collections import defaultdict

# GSMTAP hlavička
GSMTAP_PORT = 4729

# A5 algoritmy
CIPHER_MAP = {
    0: "A5/0 - ŽIADNE ŠIFROVANIE ⚠️",
    1: "A5/1 - Slabé (prelomiteľné)",
    2: "A5/2 - Veľmi slabé ❌",
    4: "A5/3 - Dobré ✅",
    8: "A5/4 - Silné ✅✅"
}

bts_info = defaultdict(dict)

def parse_gsmtap(data):
    """Parsuj GSMTAP hlavičku."""
    if len(data) < 16:
        return None
    magic, ver, hdrlen, ptype, ts_sec, ts_usec, arfcn, signal_dbm, snr_db, frame_nr, sub_type = \
        struct.unpack(">IBBBBIIHHIB", data[:28])
    return {
        "arfcn": arfcn & 0x3FFF,
        "signal_dbm": -signal_dbm,
        "frame_nr": frame_nr,
        "payload": data[hdrlen*4:]
    }

def check_cipher_mode(payload):
    """Detekuj Cipher Mode Command rámec."""
    if len(payload) < 3:
        return None
    
    # GSM RR message type 0x35 = Cipher Mode Command
    # Protokol diskriminátor + message type
    pd = payload[0] & 0x0F      # protocol discriminator
    msg_type = payload[1] & 0xFF
    
    if msg_type == 0x35:  # Cipher Mode Command
        cipher_setting = payload[2] & 0x07
        return cipher_setting
    return None

def check_system_info(payload, arfcn):
    """Zachyť System Info pre identifikáciu BTS."""
    if len(payload) < 4:
        return
    msg_type = payload[1] & 0xFF
    
    if msg_type == 0x1B:  # System Information Type 3
        # MCC/MNC/LAC/CI
        if len(payload) >= 10:
            mcc_mnc = payload[4:7]
            lac = struct.unpack(">H", payload[7:9])[0]
            ci = struct.unpack(">H", payload[9:11])[0]
            bts_info[arfcn]["LAC"] = lac
            bts_info[arfcn]["CI"] = ci

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", GSMTAP_PORT))
    sock.settimeout(1.0)
    
    print("🔍 GSM Encryption Detector spustený")
    print("=" * 50)
    print("Čakám na GSM rámce z grgsm_livemon...")
    print()
    
    detected = {}
    
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            parsed = parse_gsmtap(data)
            
            if not parsed:
                continue
                
            arfcn = parsed["arfcn"]
            payload = parsed["payload"]
            
            # Zbieraj info o BTS
            check_system_info(payload, arfcn)
            
            # Hľadaj šifrovanie
            cipher = check_cipher_mode(payload)
            
            if cipher is not None and arfcn not in detected:
                detected[arfcn] = cipher
                info = bts_info.get(arfcn, {})
                
                print(f"📡 ARFCN: {arfcn:4d} | "
                      f"LAC: {info.get('LAC','?'):5} | "
                      f"CI: {info.get('CI','?'):5} | "
                      f"Signal: {parsed['signal_dbm']:4}dBm")
                print(f"   🔐 Šifrovanie: {CIPHER_MAP.get(cipher, f'Neznáme (0x{cipher:02x})')}")
                print()
                
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            print("\n📊 Súhrn:")
            print("=" * 50)
            for arfcn, cipher in detected.items():
                print(f"ARFCN {arfcn}: {CIPHER_MAP.get(cipher, 'Neznáme')}")
            break

if __name__ == "__main__":
    main()
