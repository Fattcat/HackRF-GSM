#!/usr/bin/env python3
"""
GSM šifrovanie detektor
Číta z grgsm UDP streamu a reportuje šifrovanie každej BTS

⚠️  UPOZORNENIE: Tento nástroj je určený len na:
    - Vlastné testovacie siete
    - Vzdelávacie účely v izolovanom prostredí
    - Pasívny monitoring tam, kde to dovoľuje zákon
    
    Odchyt GSM prevádzky bez súhlasu operátora môže byť nelegálny.
"""

import socket
import struct
from collections import defaultdict
from datetime import datetime

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
    """
    Parsuj GSMTAP hlavičku - bezpečnejšia verzia.
    GSMTAP hlavička má premennú dĺžku (násobok 4 bajtov).
    """
    if len(data) < 16:
        return None
    
    try:
        # Verzia a dĺžka hlavičky v 32-bit slovách
        version = data[0]
        hdrlen_words = data[1]
        hdrlen_bytes = hdrlen_words * 4
        
        if len(data) < hdrlen_bytes:
            return None
        
        # ARFCN je na offsete 8-9 (big endian)
        arfcn = struct.unpack(">H", data[8:10])[0] & 0x3FFF
        
        # Signal level je na offsete 10-11 (signed short, dBm)
        signal_dbm = struct.unpack(">h", data[10:12])[0]
        
        # Frame number na offsete 16-18 (3 bajty)
        frame_nr = 0
        if len(data) >= hdrlen_bytes + 3:
            frame_nr = struct.unpack(">I", b'\x00' + data[16:19])[0] & 0xFFFFFF
        
        return {
            "arfcn": arfcn,
            "signal_dbm": signal_dbm,
            "frame_nr": frame_nr,
            "payload": data[hdrlen_bytes:]
        }
    except Exception as e:
        print(f"[!] Chyba pri parse GSMTAP: {e}")
        return None

def check_cipher_mode(payload):
    """
    Detekuj Cipher Mode Command rámec.
    
    Dôležité: Správy môžu prísť s alebo bez LAPDm hlavičky:
    - BCCH/CCCH: Žiadna LAPDm, začína Protocol Discriminatorom
    - DCCH/SDCCH: 3-bajtová LAPDm hlavička (Address, Control, Length)
    
    Cipher Mode Command má message type 0x35
    """
    if len(payload) < 3:
        return None
    
    # Skúsme nájsť Message Type 0x35 na rôznych pozíciách
    
    # Možnosť 1: Priamo (BCCH/CCCH - zriedkavé pre Cipher Mode)
    # Offset 0 = PD, Offset 1 = Message Type
    if len(payload) >= 3 and (payload[0] & 0x0F) in [0x06, 0x08, 0x0A]:  # RR, MM, CC
        if payload[1] == 0x35:  # Cipher Mode Command
            cipher_setting = payload[2] & 0x07
            return cipher_setting
    
    # Možnosť 2: S LAPDm hlavičkou (DCCH/SDCCH - bežné)
    # LAPDm: 3 bajty (Address, Control, Length)
    # Potom: PD (offset 3), Message Type (offset 4), Cipher Setting (offset 5)
    if len(payload) >= 6:
        # Skontroluj či vyzerá ako LAPDm (Control byte často 0x03 pre UI)
        if payload[1] in [0x03, 0x07, 0x0F]:  # Typické LAPDm control bytes
            if payload[4] == 0x35:  # Cipher Mode Command
                cipher_setting = payload[5] & 0x07 if len(payload) > 5 else 0
                return cipher_setting
    
    # Možnosť 3: Hľadaj 0x35 v prvých 10 bajtoch (fallback)
    for i in range(min(len(payload) - 2, 10)):
        if payload[i] == 0x35:
            if i + 1 < len(payload):
                return payload[i + 1] & 0x07
    
    return None

def check_system_info(payload, arfcn):
    """
    Zachyť System Information pre identifikáciu BTS.
    System Information Type 3 obsahuje LAC a Cell Identity.
    """
    if len(payload) < 12:
        return
    
    try:
        # Bez LAPDm (BCCH)
        if (payload[0] & 0x0F) == 0x06:  # RR Protocol Discriminator
            msg_type = payload[1] & 0xFF
            
            if msg_type == 0x1B:  # System Information Type 3
                # Offsety pre SI3 môžu variovať, skúsme štandardnú štruktúru
                if len(payload) >= 12:
                    # MCC/MNC sú zakódované v BCD
                    # LAC na offsete 7-8, CI na offsete 9-10
                    lac = struct.unpack(">H", payload[7:9])[0] if len(payload) >= 9 else 0
                    ci = struct.unpack(">H", payload[9:11])[0] if len(payload) >= 11 else 0
                    
                    bts_info[arfcn]["LAC"] = lac
                    bts_info[arfcn]["CI"] = ci
                    bts_info[arfcn]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        
        # S LAPDm hlavičkou
        elif len(payload) >= 8 and payload[1] in [0x03, 0x07]:
            msg_type = payload[5] & 0xFF if len(payload) > 5 else 0
            
            if msg_type == 0x1B:
                if len(payload) >= 15:
                    lac = struct.unpack(">H", payload[11:13])[0]
                    ci = struct.unpack(">H", payload[13:15])[0]
                    bts_info[arfcn]["LAC"] = lac
                    bts_info[arfcn]["CI"] = ci
                    bts_info[arfcn]["last_seen"] = datetime.now().strftime("%H:%M:%S")
    except Exception:
        pass

def main():
    print("=" * 60)
    print("🔍 GSM Encryption Detector")
    print("=" * 60)
    print("⚠️  UPOZORNENIE: Len na legálne použitie!")
    print("    - Vlastné siete / Izolované prostredie")
    print("    - Vzdelávacie účely")
    print("=" * 60)
    print(f"📡 Čakám na GSMTAP na porte {GSMTAP_PORT}...")
    print("   (Spustite grgsm_livemon alebo grgsm_scanner)")
    print()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(("127.0.0.1", GSMTAP_PORT))
    except OSError as e:
        print(f"[!] Chyba: Port {GSMTAP_PORT} je už používaný")
        print(f"    Ukončite iné inštancie grgsm_livemon")
        print(f"    Detail: {e}")
        return
    
    sock.settimeout(1.0)
    
    detected = {}
    frame_count = 0
    
    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                frame_count += 1
                
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
                          f"LAC: {info.get('LAC', '?'):5} | "
                          f"CI: {info.get('CI', '?'):5} | "
                          f"Signal: {parsed['signal_dbm']:4}dBm")
                    print(f"   🔐 Šifrovanie: {CIPHER_MAP.get(cipher, f'Neznáme (0x{cipher:02x})')}")
                    print()
                    
            except socket.timeout:
                # Každých 10 sekúnd status
                if frame_count % 10 == 0:
                    print(f"   ... čakám ({len(detected)} BTS detekovaných)", end='\r')
                continue
                
    except KeyboardInterrupt:
        print("\n\n📊 SÚHRN DETEKOVANÝCH BTS")
        print("=" * 60)
        
        if not detected:
            print("Žiadne šifrovanie nebolo detekované.")
            print()
            print("⚠️  POZNÁMKA: Pasívna detekcia na BCCH nie je 100% spoľahlivá.")
            print("    Cipher Mode Command sa vysiela na SDCCH/TCH počas:")
            print("    - Registrácie telefónu")
            print("    - Prichádzajúceho/odchádzajúceho hovoru")
            print("    - SMS správy")
            print()
            print("    Ak nebola žiadna aktivita, šifrovanie sa nezachytí.")
        else:
            for arfcn, cipher in sorted(detected.items()):
                info = bts_info.get(arfcn, {})
                print(f"ARFCN {arfcn:4d} | LAC {info.get('LAC', '?'):5} | "
                      f"CI {info.get('CI', '?'):5} | {CIPHER_MAP.get(cipher, 'Neznáme')}")
        
        print("=" * 60)
        print(f"Spracovaných rámcev: {frame_count}")
        
    finally:
        sock.close()

if __name__ == "__main__":
    main()
