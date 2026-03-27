#!/usr/bin/env python3
"""
GSM Listener - počúva GSMTAP z grgsm_livemon
Spusti v druhom termináli po spustení grgsm_livemon
"""

import socket
import struct
import sys
from datetime import datetime
from collections import defaultdict

GSMTAP_PORT = 4729

# A5 algoritmy
CIPHER_MAP = {
    0: ("A5/0", "BEZ ŠIFROVANIA ⚠️"),
    1: ("A5/1", "Slabé"),
    2: ("A5/2", "Veľmi slabé"),
    4: ("A5/3", "Dobré ✓"),
    8: ("A5/4", "Silné ✓✓"),
}

# Slovenskí operátori
OPERATORS = {
    ("231", "01"): "Orange",
    ("231", "02"): "Telekom",
    ("231", "04"): "O2",
    ("231", "15"): "4ka",
}

class GSMListener:
    def __init__(self):
        self.bts = {}  # arfcn -> info
        self.ciphers = {}  # arfcn -> cipher_type
        self.packet_count = 0
        self.sock = None
    
    def start(self):
        """Spusti UDP listener."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.sock.bind(("127.0.0.1", GSMTAP_PORT))
            print(f"[✓] Listener spustený na porte {GSMTAP_PORT}")
            print(f"[i] Čakám na GSMTAP pakety z grgsm_livemon...")
            print()
        except OSError as e:
            print(f"[✗] Chyba: Port {GSMTAP_PORT} je obsadený")
            print(f"    Ukonči iné grgsm_livemon procesy:")
            print(f"    sudo killall grgsm_livemon")
            sys.exit(1)
        
        self.sock.settimeout(1.0)
        self._listen()
    
    def _listen(self):
        """Hlavná slučka - počúvaj pakety."""
        try:
            while True:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    self.packet_count += 1
                    self._process_packet(data)
                    
                    # Status každých 100 paketov
                    if self.packet_count % 100 == 0:
                        print(f"[i] Spracovaných {self.packet_count} paketov... "
                              f"({len(self.bts)} BTS, {len(self.ciphers)} šifrovaní)", 
                              end='\r')
                        
                except socket.timeout:
                    continue
                    
        except KeyboardInterrupt:
            print("\n\n" + "=" * 60)
            self._print_results()
        finally:
            if self.sock:
                self.sock.close()
    
    def _process_packet(self, data):
        """Spracuj jeden GSMTAP paket."""
        if len(data) < 16:
            return
        
        # === GSMTAP Header ===
        # Offset 0: version
        # Offset 1: header length (v 32-bit slovách)
        # Offset 8-9: ARFCN (big endian)
        # Offset 10-11: Signal level (signed short, dBm)
        
        hdrlen_words = data[1]
        hdrlen_bytes = hdrlen_words * 4
        
        if len(data) < hdrlen_bytes:
            return
        
        try:
            arfcn = struct.unpack(">H", data[8:10])[0] & 0x3FFF
            signal_dbm = struct.unpack(">h", data[10:12])[0]
        except:
            return
        
        payload = data[hdrlen_bytes:]
        
        if len(payload) < 3:
            return
        
        # === Detekuj System Information (BTS info) ===
        self._check_system_info(payload, arfcn, signal_dbm)
        
        # === Detekuj Cipher Mode Command ===
        self._check_cipher_mode(payload, arfcn)
    
    def _check_system_info(self, payload, arfcn, signal_dbm):
        """
        Detekuj System Information Type 3 (obsahuje LAC, CI, MCC, MNC)
        Message type: 0x1B
        """
        if len(payload) < 12:
            return
        
        # Skús bez LAPDm (BCCH)
        if (payload[0] & 0x0F) == 0x06:  # RR Protocol Discriminator
            msg_type = payload[1] & 0xFF
            
            if msg_type == 0x1B:  # System Information Type 3
                # Parsuj LAC a CI
                if len(payload) >= 11:
                    try:
                        lac = struct.unpack(">H", payload[7:9])[0]
                        ci = struct.unpack(">H", payload[9:11])[0]
                        
                        # MCC/MNC sú v BCD formáte - zjednodušene
                        mcc = ""
                        mnc = ""
                        if len(payload) >= 7:
                            # Byte 4-6 obsahujú MCC/MNC
                            mcc_mnc_bytes = payload[4:7]
                            mcc = self._decode_bcd(mcc_mnc_bytes[:3])
                            mnc = self._decode_bcd(mcc_mnc_bytes[2:3] + mcc_mnc_bytes[1:2])
                        
                        if arfcn not in self.bts:
                            self.bts[arfcn] = {
                                'lac': lac,
                                'ci': ci,
                                'mcc': mcc,
                                'mnc': mnc,
                                'signal': signal_dbm,
                                'first_seen': datetime.now().strftime("%H:%M:%S")
                            }
                            
                            op = OPERATORS.get((mcc, mnc), f"MCC{mcc}/MNC{mnc}" if mcc else "?")
                            print(f"\n[📡] NOVÁ BTS DETEKOVANÁ")
                            print(f"    ARFCN: {arfcn}")
                            print(f"    Freq:  {self._arfcn_to_freq(arfcn):.1f} MHz")
                            print(f"    LAC:   {lac}")
                            print(f"    CI:    {ci}")
                            print(f"    MCC:   {mcc}")
                            print(f"    MNC:   {mnc}")
                            print(f"    Operátor: {op}")
                            print(f"    Signal: {signal_dbm} dBm")
                            
                    except Exception as e:
                        pass  # Silent fail pre neúplné dáta
        
        # Skús s LAPDm (3 bajty header)
        elif len(payload) >= 15 and payload[1] in [0x03, 0x07, 0x0F]:
            if len(payload) > 5 and payload[5] == 0x1B:
                try:
                    lac = struct.unpack(">H", payload[11:13])[0]
                    ci = struct.unpack(">H", payload[13:15])[0]
                    
                    if arfcn not in self.bts:
                        self.bts[arfcn] = {
                            'lac': lac,
                            'ci': ci,
                            'mcc': '',
                            'mnc': '',
                            'signal': signal_dbm,
                            'first_seen': datetime.now().strftime("%H:%M:%S")
                        }
                        
                        print(f"\n[📡] NOVÁ BTS DETEKOVANÁ")
                        print(f"    ARFCN: {arfcn}")
                        print(f"    LAC:   {lac}")
                        print(f"    CI:    {ci}")
                        print(f"    Signal: {signal_dbm} dBm")
                        
                except:
                    pass
    
    def _check_cipher_mode(self, payload, arfcn):
        """
        Detekuj Cipher Mode Command
        Message type: 0x35
        """
        if len(payload) < 3:
            return
        
        cipher = None
        
        # Skús bez LAPDm
        if (payload[0] & 0x0F) in [0x06, 0x08, 0x0A]:
            if payload[1] == 0x35:
                cipher = payload[2] & 0x07
        
        # Skús s LAPDm (3 bajty header)
        if cipher is None and len(payload) >= 6:
            if payload[1] in [0x03, 0x07, 0x0F]:
                if payload[4] == 0x35:
                    cipher = payload[5] & 0x07
        
        # Fallback - hľadaj 0x35 v prvých bajtoch
        if cipher is None:
            for i in range(min(len(payload) - 2, 10)):
                if payload[i] == 0x35 and i + 1 < len(payload):
                    cipher = payload[i + 1] & 0x07
                    break
        
        if cipher is not None and arfcn not in self.ciphers:
            self.ciphers[arfcn] = cipher
            algo, desc = CIPHER_MAP.get(cipher, ("?", f"Neznáme (0x{cipher:02x})"))
            
            print(f"\n[🔐] ŠIFROVANIE DETEKOVANÉ")
            print(f"    ARFCN: {arfcn}")
            print(f"    Algoritmus: {algo}")
            print(f"    Status: {desc}")
    
    def _arfcn_to_freq(self, arfcn):
        """Konvertuj ARFCN na frekvenciu (MHz)."""
        if arfcn >= 1 and arfcn <= 124:  # GSM900
            return 935.0 + (arfcn * 0.2)
        elif arfcn >= 975 and arfcn <= 1023:  # EGSM900
            return 935.0 + ((arfcn - 1024) * 0.2)
        elif arfcn >= 512 and arfcn <= 885:  # DCS1800
            return 1805.0 + ((arfcn - 512) * 0.2)
        return 0.0
    
    def _decode_bcd(self, data):
        """Dekóduj BCD formát (MCC/MNC)."""
        result = ""
        for byte in data:
            result += str(byte & 0x0F)
            result += str((byte >> 4) & 0x0F)
        return result.rstrip('F')
    
    def _print_results(self):
        """Vypíš výsledky."""
        print("=" * 60)
        print(" GSM SCANNER - VÝSLEDKY")
        print("=" * 60)
        print()
        print(f"Celkovo paketov: {self.packet_count}")
        print(f"Detekovaných BTS:  {len(self.bts)}")
        print(f"Detekovaných šifrovaní: {len(self.ciphers)}")
        print()
        
        if self.bts:
            print("-" * 60)
            print(" DETEKOVANÉ BTS")
            print("-" * 60)
            print(f"{'ARFCN':>6} | {'Freq':>8} | {'LAC':>5} | {'CI':>6} | {'Signal':>8} | {'Operátor':>12}")
            print("-" * 60)
            
            for arfcn in sorted(self.bts.keys()):
                info = self.bts[arfcn]
                freq = self._arfcn_to_freq(arfcn)
                op = OPERATORS.get((info['mcc'], info['mnc']), "?")
                print(f"{arfcn:>6} | {freq:>7.1f}MHz | {info['lac']:>5} | {info['ci']:>6} | "
                      f"{info['signal']:>7}dBm | {op:>12}")
        
        if self.ciphers:
            print()
            print("-" * 60)
            print(" DETEKOVANÉ ŠIFROVANIE")
            print("-" * 60)
            print(f"{'ARFCN':>6} | {'Algoritmus':>10} | {'Status':>20}")
            print("-" * 60)
            
            for arfcn in sorted(self.ciphers.keys()):
                cipher = self.ciphers[arfcn]
                algo, desc = CIPHER_MAP.get(cipher, ("?", "Neznáme"))
                print(f"{arfcn:>6} | {algo:>10} | {desc:>20}")
        
        print()
        print("=" * 60)
        
        # Warning pre nešifrované BTS
        unencrypted = [a for a in self.bts.keys() if a in self.ciphers and self.ciphers[a] == 0]
        if unencrypted:
            print()
            print("⚠️  UPOZORNENIE: Nasledujúce BTS nemajú šifrovanie (A5/0):")
            for arfcn in unencrypted:
                freq = self._arfcn_to_freq(arfcn)
                print(f"   - ARFCN {arfcn} ({freq:.1f} MHz)")
        
        print()

def main():
    print("=" * 60)
    print(" GSM LISTENER - GSMTAP Decoder")
    print("=" * 60)
    print()
    print("Návod:")
    print("  1. V termináli 1: grgsm_livemon -f 935200000 -g 40")
    print("  2. V termináli 2: python3 gsm_listener.py")
    print()
    print("Pre ukončenie stlač Ctrl+C")
    print("=" * 60)
    print()
    
    listener = GSMListener()
    listener.start()

if __name__ == "__main__":
    main()
