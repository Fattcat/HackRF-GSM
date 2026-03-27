#!/usr/bin/env python3
"""
GSM Scanner - DEBUG verzia
Podrobne loguje každý krok pre diagnostiku
"""

import subprocess
import socket
import struct
import threading
import time
import sys
import os
import re
from datetime import datetime

GSMTAP_PORT = 4729

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}")

def test_hackrf():
    """Test 1: Over HackRF."""
    log("Test 1: Detekcia HackRF...", "TEST")
    try:
        r = subprocess.run(["hackrf_info"], capture_output=True, text=True, timeout=5)
        if "HackRF" in r.stdout:
            log("HackRF One nájdený ✓", "OK")
            return True
        else:
            log("HackRF nenájdený ✗", "ERROR")
            print(r.stdout)
            print(r.stderr)
            return False
    except Exception as e:
        log(f"Chyba: {e}", "ERROR")
        return False

def test_grgsm_scanner():
    """Test 2: Over grgsm_scanner."""
    log("Test 2: grgsm_scanner...", "TEST")
    
    if not subprocess.run(["which", "grgsm_scanner"], capture_output=True).returncode == 0:
        log("grgsm_scanner nenájdený ✗", "ERROR")
        return False
    
    log("grgsm_scanner nájdený ✓", "OK")
    
    # Spusti scanner na 15 sekúnd
    log("Spúšťam grgsm_scanner (15s timeout)...", "RUN")
    
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen", "DISPLAY": ""}
    
    try:
        r = subprocess.run(
            ["grgsm_scanner", "--band=EGSM900", "--gain=40"],
            capture_output=True, text=True, timeout=15, env=env
        )
        
        output = r.stdout + r.stderr
        
        # Ulož output pre analýzu
        with open("/tmp/grgsm_scanner_debug.txt", "w") as f:
            f.write(output)
        
        log(f"Output uložený v /tmp/grgsm_scanner_debug.txt", "INFO")
        log(f"Dĺžka outputu: {len(output)} znakov", "INFO")
        
        # Hľadaj ARFCN v outpute
        arfcn_pattern = re.compile(r"ARFCN[:\s]+(\d+)", re.IGNORECASE)
        matches = arfcn_pattern.findall(output)
        
        if matches:
            log(f"Nájdených {len(matches)} ARFCN: {matches[:5]}", "OK")
            
            # Ukáž prvý riadok s ARFCN
            for line in output.splitlines():
                if "ARFCN" in line:
                    log(f"Príklad riadku: {line[:100]}", "SAMPLE")
                    break
            
            return True
        else:
            log("Žiadne ARFCN nenájdené ✗", "WARNING")
            log("Možné príčiny:", "INFO")
            log("  - Žiadny GSM signál v dosahu", "INFO")
            log("  - Zlý gain (skús 30-50)", "INFO")
            log("  - Zlé pásmo (skús GSM900 alebo DCS1800)", "INFO")
            log("  - Anténa nie je pripojená", "INFO")
            
            # Ukáž posledných 10 riadkov outputu
            log("Posledných 10 riadkov outputu:", "SAMPLE")
            for line in output.splitlines()[-10:]:
                log(f"  {line}", "SAMPLE")
            
            return False
            
    except subprocess.TimeoutExpired:
        log("Timeout - scanner bežal príliš dlho", "WARNING")
        return False
    except Exception as e:
        log(f"Chyba: {e}", "ERROR")
        return False

def test_gsmtap_listener():
    """Test 3: Over GSMTAP port."""
    log("Test 3: GSMTAP listener...", "TEST")
    
    # Skontroluj či port nie je obsadený
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(("127.0.0.1", GSMTAP_PORT))
        log(f"Port {GSMTAP_PORT} je dostupný ✓", "OK")
        sock.close()
        return True
    except OSError as e:
        log(f"Port {GSMTAP_PORT} je obsadený ✗: {e}", "ERROR")
        log("Ukonči iné inštancie grgsm_livemon:", "INFO")
        log("  sudo killall grgsm_livemon", "INFO")
        return False

def test_gsmtap_capture():
    """Test 4: Zachyť GSMTAP dáta."""
    log("Test 4: Zachytávanie GSMTAP...", "TEST")
    log("POZOR: Tento test vyžaduje bežiaci grgsm_livemon!", "WARNING")
    log("V inom termináli spusti: grgsm_livemon -f 935200000 -g 40", "INFO")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", GSMTAP_PORT))
    sock.settimeout(10.0)
    
    log("Čakám na GSMTAP pakety (10s)...", "RUN")
    
    received = 0
    try:
        while received < 10:
            data, addr = sock.recvfrom(4096)
            received += 1
            log(f"Paket {received}: {len(data)} bajtov z {addr}", "OK")
            
            # Parsuj hlavičku
            if len(data) >= 16:
                hdrlen = data[1] * 4
                arfcn = struct.unpack(">H", data[8:10])[0] & 0x3FFF
                log(f"  ARFCN: {arfcn}, Header length: {hdrlen}", "INFO")
    except socket.timeout:
        log(f"Timeout - prijatých len {received} paketov", "WARNING")
    except Exception as e:
        log(f"Chyba: {e}", "ERROR")
    finally:
        sock.close()
    
    if received > 0:
        log(f"GSMTAP funguje ✓ ({received} paketov)", "OK")
        return True
    else:
        log("Žiadne GSMTAP dáta ✗", "ERROR")
        log("Skontroluj že grgsm_livemon beží s --gsmtap 127.0.0.1:4729", "INFO")
        return False

def parse_scanner_output():
    """Test 5: Parsuj uložený output."""
    log("Test 5: Analýza scanner outputu...", "TEST")
    
    try:
        with open("/tmp/grgsm_scanner_debug.txt", "r") as f:
            content = f.read()
    except FileNotFoundError:
        log("Nájdený /tmp/grgsm_scanner_debug.txt - najprv spusti Test 2", "ERROR")
        return False
    
    # Skús rôzne regex patterny
    patterns = [
        r"ARFCN:\s*(\d+).*?Freq:\s*([\d.]+)M.*?CID:\s*(\d+).*?LAC:\s*(\d+).*?MCC:\s*(\d+).*?MNC:\s*(\w+).*?Pwr:\s*(-?[\d.]+)",
        r"ARFCN[:\s]+(\d+)",
        r"(\d+)\s+[\d.]+\s+\w+\s+\d+\s+\d+",
    ]
    
    for i, pattern in enumerate(patterns):
        matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
        log(f"Pattern {i+1}: {len(matches)} matchov", "INFO")
        if matches:
            log(f"  Prvý match: {matches[0]}", "SAMPLE")
    
    return True

def main():
    print("=" * 60)
    print(" GSM Scanner - DEBUG Diagnostika")
    print("=" * 60)
    print()
    
    results = {}
    
    # Test 1
    results["hackrf"] = test_hackrf()
    print()
    
    # Test 2
    results["scanner"] = test_grgsm_scanner()
    print()
    
    # Test 3
    results["port"] = test_gsmtap_listener()
    print()
    
    # Test 4 (vyžaduje bežiaci livemon)
    print("=" * 60)
    print("Pred Testom 4 spusti v inom termináli:")
    print("  grgsm_livemon -f 935200000 -g 40")
    print()
    input("Stlač ENTER keď je grgsm_livemon spustený (alebo Ctrl+C preskoč)...")
    results["gsmtap"] = test_gsmtap_capture()
    print()
    
    # Test 5
    results["parse"] = parse_scanner_output()
    print()
    
    # Súhrn
    print("=" * 60)
    print(" SÚHRN")
    print("=" * 60)
    
    for test, result in results.items():
        status = "✓" if result else "✗"
        print(f"  {test}: {status}")
    
    print()
    
    if results["hackrf"] and results["scanner"]:
        print("[OK] Základné testy prešli - hardware funguje")
        if not results["gsmtap"]:
            print("[WARNING] GSMTAP nefunguje - problém s grgsm_livemon")
    else:
        print("[ERROR] Niektoré testy zlyhali - pozri výstup vyššie")
    
    print()
    print("Debug logy uložené v:")
    print("  /tmp/grgsm_scanner_debug.txt")
    print("=" * 60)

if __name__ == "__main__":
    main()
