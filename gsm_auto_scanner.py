#!/usr/bin/env python3
"""
GSM Auto Scanner + Encryption Detector
=======================================
Čisto terminálový – žiadne GUI okná.
Optimalizované pre Raspberry Pi 4 + HackRF One.

⚠️  LEGÁLNE UPOZORNENIE:
    Tento nástroj používajte len na:
    - Vlastné testovacie siete (Faraday cage)
    - Vzdelávacie účely v izolovanom prostredí
    - Pasívny monitoring tam, kde to dovoľuje miestny zákon
    
    Odchyt GSM prevádzky bez súhlasu operátora môže byť trestný čin.
    Autor nepreberá zodpovednosť za zneužitie tohto softvéru.

Spustenie:
  source venv/bin/activate
  sudo python3 gsm_auto_scanner.py
  sudo python3 gsm_auto_scanner.py --band GSM900 --gain 40
  sudo python3 gsm_auto_scanner.py --scan-only
"""

import subprocess
import socket
import struct
import threading
import time
import json
import sys
import os
import re
import argparse
import signal
import shutil
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime

# ── rich ─────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (Progress, SpinnerColumn,
                               BarColumn, TextColumn, TimeElapsedColumn)
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None

MARKUP_RE = re.compile(r"\[/?[^\]]*\]")

def cprint(msg):
    """Print s podporou Rich markup alebo čistý text."""
    if RICH and console:
        console.print(msg)
    else:
        print(MARKUP_RE.sub("", msg))

def clog(msg):
    """Log s časovou pečiatkou."""
    ts = datetime.now().strftime("%H:%M:%S")
    cprint(f"[dim]{ts}[/dim] {msg}" if RICH else f"{ts} {msg}")

# ─────────────────────────────────────────────────────────────────────────────

GSMTAP_PORT = 4729
SCAN_TIMEOUT = 30
CAPTURE_TIME = 45

# Slovenskí operátori
SK_OPERATORS = {
    ("231", "01"): "Orange SK",
    ("231", "02"): "Telekom SK",
    ("231", "03"): "Juro.sk",
    ("231", "04"): "O2 SK",
    ("231", "05"): "Tesco Mobile",
    ("231", "06"): "O2 SK MVNO",
    ("231", "15"): "4ka",
}

# A5 algoritmy s farbami pre Rich
CIPHER_MAP = {
    0: ("A5/0", "BEZ ŠIFROVANIA", "red bold"),
    1: ("A5/1", "Slabé", "yellow"),
    2: ("A5/2", "Veľmi slabé", "red"),
    4: ("A5/3", "Dobré", "green"),
    8: ("A5/4", "Silné", "bright_green"),
}

# GSM pásma dostupné na Slovensku
BANDS_SK = ["GSM900", "EGSM900", "DCS1800"]

# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BTSInfo:
    arfcn: int
    freq_mhz: float
    band: str
    power_dbm: float = -999.0
    mcc: str = ""
    mnc: str = ""
    lac: int = 0
    ci: int = 0
    cipher: Optional[int] = None
    seen_at: str = ""
    cipher_detected_at: str = ""

    @property
    def operator(self):
        return SK_OPERATORS.get((self.mcc, self.mnc),
               f"MCC{self.mcc}/MNC{self.mnc}" if self.mcc else "?")

    @property
    def cipher_label(self):
        if self.cipher is None:
            return ("?", "Nezistené", "dim")
        return CIPHER_MAP.get(self.cipher,
               ("?", f"0x{self.cipher:02x}", "white"))

# ─────────────────────────────────────────────────────────────────────────────

def detect_device() -> str:
    """
    Detekuj pripojené SDR zariadenie.
    Priorita: HackRF > RTL-SDR > USRP
    """
    # HackRF One
    if shutil.which("hackrf_info"):
        try:
            r = subprocess.run(["hackrf_info"],
                capture_output=True, text=True, timeout=5)
            if "Serial number" in r.stdout or "HackRF" in r.stdout:
                cprint("  [green]✓ HackRF One nájdený[/green]")
                return "hackrf"
        except Exception:
            pass
    
    # RTL-SDR
    if shutil.which("rtl_test"):
        try:
            r = subprocess.run(["rtl_test", "-t"],
                capture_output=True, text=True, timeout=5)
            if "Found" in r.stderr or "Found" in r.stdout:
                cprint("  [yellow]✓ RTL-SDR nájdený[/yellow]")
                return "rtlsdr"
        except Exception:
            pass
    
    # USRP (menej pravdepodobné na RPi)
    if shutil.which("uhd_find_devices"):
        try:
            r = subprocess.run(["uhd_find_devices"],
                capture_output=True, text=True, timeout=8)
            if any(x in r.stdout for x in ("B2", "B200", "B210", "USRP")):
                cprint("  [cyan]✓ USRP nájdený[/cyan]")
                return "uhd"
        except Exception:
            pass
    
    return "none"

# ─────────────────────────────────────────────────────────────────────────────

SCANNER_RE = re.compile(
    r"ARFCN:\s*(\d+).*?Freq:\s*([\d.]+)M.*?"
    r"CID:\s*(\d+).*?LAC:\s*(\d+).*?"
    r"MCC:\s*(\d+).*?MNC:\s*(\w+).*?"
    r"Pwr:\s*(-?[\d.]+)",
    re.IGNORECASE | re.DOTALL
)

def run_scanner(band: str, gain: int, timeout: int) -> List[BTSInfo]:
    """
    Spusti grgsm_scanner pre dané pásmo.
    """
    if not shutil.which("grgsm_scanner"):
        cprint("[red]✗ grgsm_scanner nebol nájdený → sudo apt install gr-gsm[/red]")
        cprint("[dim]  Alebo nainštaluj zo zdroja: https://github.com/ptrkrysik/gr-gsm[/dim]")
        return []
    
    cprint(f"  Skenujem [cyan]{band}[/cyan]...")
    
    env = {**os.environ, "DISPLAY": "", "QT_QPA_PLATFORM": "offscreen"}
    
    # HackRF špecifické nastavenia
    device_args = []
    device = detect_device()
    if device == "hackrf":
        device_args = ["--args", "hackrf=0"]
    
    try:
        cmd = ["grgsm_scanner", f"--band={band}", f"--gain={gain}"] + device_args
        r = subprocess.run(cmd, capture_output=True, text=True, 
                          timeout=timeout, env=env)
        output = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        cprint(f"  [yellow]⏱ Timeout {band}[/yellow]")
        return []
    except Exception as e:
        cprint(f"  [red]Chyba: {e}[/red]")
        return []

    found = []
    seen_arfcns = set()
    
    for line in output.splitlines():
        m = SCANNER_RE.search(line)
        if not m:
            continue
        
        arfcn = int(m.group(1))
        
        # Filter duplikátov
        if arfcn in seen_arfcns:
            continue
        seen_arfcns.add(arfcn)
        
        b = BTSInfo(
            arfcn=arfcn,
            freq_mhz=float(m.group(2)),
            band=band,
            ci=int(m.group(3)),
            lac=int(m.group(4)),
            mcc=m.group(5).zfill(3),
            mnc=m.group(6).zfill(2),
            power_dbm=float(m.group(7)),
            seen_at=datetime.now().strftime("%H:%M:%S"),
        )
        found.append(b)
        
        cprint(
            f"    [green]▸[/green] ARFCN [bold]{b.arfcn:4d}[/bold]"
            f" | {b.freq_mhz:.1f} MHz"
            f" | {b.operator:15s}"
            f" | [yellow]{b.power_dbm:.0f} dBm[/yellow]"
        )
    
    if not found:
        cprint(f"  [dim]Žiadne BTS v {band}[/dim]")
    
    return found

# ─────────────────────────────────────────────────────────────────────────────

class CipherListener:
    """
    UDP listener pre GSMTAP stream.
    Detekuje Cipher Mode Command správy.
    """
    def __init__(self):
        self.results: Dict[int, int] = {}
        self._lock = threading.Lock()
        self._sock = None
        self._active = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self._sock.bind(("127.0.0.1", GSMTAP_PORT))
        except OSError as e:
            cprint(f"[red]Nemožem otvoriť UDP {GSMTAP_PORT}: {e}[/red]")
            cprint("[dim]  Ukončite iné inštancie grgsm_livemon[/dim]")
            return
        
        self._sock.settimeout(0.5)
        self._active = True
        threading.Thread(target=self._loop, daemon=True).start()
        cprint("  [green]✓ Cipher listener spustený[/green]")

    def stop(self):
        self._active = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _loop(self):
        while self._active:
            try:
                data, _ = self._sock.recvfrom(4096)
                self._parse(data)
            except socket.timeout:
                continue
            except Exception:
                break

    def _parse(self, data: bytes):
        """
        Parsuj GSMTAP a hľadaj Cipher Mode Command.
        """
        if len(data) < 16:
            return
        
        try:
            # GSMTAP header length
            hdrlen_words = data[1]
            hdrlen_bytes = hdrlen_words * 4
            
            if len(data) < hdrlen_bytes:
                return
            
            # ARFCN
            arfcn = struct.unpack(">H", data[8:10])[0] & 0x3FFF
            payload = data[hdrlen_bytes:]
            
        except Exception:
            return
        
        if len(payload) < 3:
            return
        
        # Hľadaj Cipher Mode Command (0x35)
        cipher = None
        
        # Možnosť 1: Bez LAPDm
        if len(payload) >= 3 and (payload[0] & 0x0F) in [0x06, 0x08, 0x0A]:
            if payload[1] == 0x35:
                cipher = payload[2] & 0x07
        
        # Možnosť 2: S LAPDm (3 bajty header)
        if cipher is None and len(payload) >= 6:
            if payload[1] in [0x03, 0x07, 0x0F]:
                if payload[4] == 0x35:
                    cipher = payload[5] & 0x07
        
        # Možnosť 3: Fallback search
        if cipher is None:
            for i in range(min(len(payload) - 2, 10)):
                if payload[i] == 0x35 and i + 1 < len(payload):
                    cipher = payload[i + 1] & 0x07
                    break
        
        if cipher is not None:
            with self._lock:
                if arfcn not in self.results:
                    self.results[arfcn] = cipher
                    algo, desc, style = CIPHER_MAP.get(cipher, ("?", f"0x{cipher:02x}", "white"))
                    clog(f"  [magenta]🔐 ARFCN {arfcn}[/magenta]: [{style}]{algo} – {desc}[/{style}]")

# ─────────────────────────────────────────────────────────────────────────────

def find_headless() -> Optional[str]:
    """Nájdi dostupný headless gr-gsm nástroj."""
    for cmd in ["grgsm_livemon_headless", "grgsm_decode", "grgsm_capture"]:
        if shutil.which(cmd):
            return cmd
    return None

def start_capture(bts: BTSInfo, gain: int) -> Optional[subprocess.Popen]:
    """
    Spusti grgsm_livemon na zachytenie prevádzky pre danú BTS.
    """
    cmd_name = find_headless()
    
    if not cmd_name:
        # Fallback na grgsm_livemon
        if shutil.which("grgsm_livemon"):
            cmd_name = "grgsm_livemon"
        else:
            return None
    
    env = {
        **os.environ,
        "DISPLAY": "",
        "QT_QPA_PLATFORM": "offscreen",
        "GDK_BACKEND": "offscreen",
    }
    
    # HackRF špecifické argumenty
    device = detect_device()
    args = []
    
    if device == "hackrf":
        args.extend(["--args", "hackrf=0"])
    
    # Sample rate pre GSM (2 Msps je štandard, ale osmosdr často žiada 4 Msps)
    args.extend(["-s", "4000000"])
    
    cmds = {
        "grgsm_livemon_headless": [
            "grgsm_livemon_headless",
            f"-f", str(bts.freq_mhz * 1e6),
            f"-g", str(gain),
        ] + args,
        "grgsm_livemon": [
            "grgsm_livemon",
            f"-f", str(bts.freq_mhz * 1e6),
            f"-g", str(gain),
        ] + args,
        "grgsm_decode": [
            "grgsm_decode",
            f"-c", str(bts.freq_mhz * 1e6),
            f"-g", str(gain),
            "--mode=BCCH",
        ] + args,
        "grgsm_capture": [
            "grgsm_capture",
            f"--freq", str(bts.freq_mhz * 1e6),
            f"--gain", str(gain),
        ] + args,
    }
    
    try:
        proc = subprocess.Popen(
            cmds.get(cmd_name, []),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        time.sleep(0.5)  # Čakaj na štart
        return proc
    except FileNotFoundError:
        return None
    except Exception as e:
        cprint(f"[red]Chyba pri štarte capture: {e}[/red]")
        return None

# ─────────────────────────────────────────────────────────────────────────────

def print_results(bts_list: List[BTSInfo]):
    """Vypíš výsledky v tabuľke."""
    if RICH and console:
        t = Table(title="GSM – analýza šifrovania",
                  show_lines=True, header_style="bold cyan", border_style="cyan")
        
        for col, w, just, sty in [
            ("ARFCN", 7, "right", "cyan"),
            ("MHz", 8, "right", "blue"),
            ("Pásmo", 9, "center", "blue"),
            ("Operátor", 16, "left", "white"),
            ("LAC", 6, "right", "dim"),
            ("CI", 6, "right", "dim"),
            ("Signal", 9, "right", "yellow"),
            ("Algo", 6, "center", ""),
            ("Stav šifr.", 20, "left", ""),
        ]:
            t.add_column(col, justify=just, width=w, style=sty)
        
        for b in sorted(bts_list, key=lambda x: x.power_dbm, reverse=True):
            algo, desc, style = b.cipher_label
            t.add_row(
                str(b.arfcn), f"{b.freq_mhz:.1f}", b.band, b.operator,
                str(b.lac), str(b.ci), f"{b.power_dbm:.0f} dBm",
                f"[{style}]{algo}[/{style}]",
                f"[{style}]{desc}[/{style}]",
            )
        
        console.print(t)
        
        # Warning pre nešifrované BTS
        no_enc = [b for b in bts_list if b.cipher == 0]
        if no_enc:
            console.print(Panel(
                "\n".join(f"  ⚠  ARFCN {b.arfcn} ({b.freq_mhz:.1f} MHz) – {b.operator}"
                          for b in no_enc),
                title="[red bold]BEZ ŠIFROVANIA – A5/0[/]", border_style="red"
            ))
    else:
        W = 95
        print("\n" + "=" * W + "\nGSM ANALÝZA – VÝSLEDKY\n" + "=" * W)
        print(f"{'ARFCN':>6}  {'MHz':>7}  {'Pásmo':>8}  {'Operátor':>15}  "
              f"{'LAC':>5}  {'CI':>5}  {'Signal':>8}  {'Algo':>5}  Stav")
        print("-" * W)
        
        for b in sorted(bts_list, key=lambda x: x.power_dbm, reverse=True):
            algo, desc, _ = b.cipher_label
            print(f"{b.arfcn:>6}  {b.freq_mhz:>7.1f}  {b.band:>8}  "
                  f"{b.operator:>15}  {b.lac:>5}  {b.ci:>5}  "
                  f"{b.power_dbm:>7.0f} dBm  {algo:>5}  {desc}")
        
        print("=" * W)

def save_json(bts_list: List[BTSInfo], path: str):
    """Ulož výsledky do JSON."""
    data = []
    for b in bts_list:
        algo, desc, _ = b.cipher_label
        data.append({
            "arfcn": b.arfcn,
            "freq_mhz": b.freq_mhz,
            "band": b.band,
            "operator": b.operator,
            "mcc": b.mcc,
            "mnc": b.mnc,
            "lac": b.lac,
            "ci": b.ci,
            "power_dbm": b.power_dbm,
            "cipher_id": b.cipher,
            "cipher_algo": algo,
            "cipher_desc": desc,
            "seen_at": b.seen_at,
            "cipher_detected_at": b.cipher_detected_at,
        })
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    
    cprint(f"\n[green]Výsledky uložené:[/green] [cyan]{path}[/cyan]")

# ─────────────────────────────────────────────────────────────────────────────

def wait_with_progress(seconds: int, stop_flag: threading.Event,
                       arfcn: int, listener: CipherListener):
    """
    Čaká 'seconds' sekúnd, prípadne skončí skôr ak je šifrovanie zachytené.
    """
    if RICH and console:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=28),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as prog:
            task = prog.add_task("  Čakám na Cipher Mode...", total=seconds)
            deadline = time.time() + seconds
            
            while time.time() < deadline and not stop_flag.is_set():
                elapsed = seconds - (deadline - time.time())
                prog.update(task, completed=elapsed)
                
                with listener._lock:
                    if arfcn in listener.results:
                        prog.update(task, completed=seconds)
                        break
                
                time.sleep(0.4)
    else:
        deadline = time.time() + seconds
        while time.time() < deadline and not stop_flag.is_set():
            with listener._lock:
                if arfcn in listener.results:
                    break
            
            remaining = int(deadline - time.time())
            print(f"  Čakám... {remaining:3d}s zostáva\r", end="", flush=True)
            time.sleep(0.5)
        print()

# ─────────────────────────────────────────────────────────────────────────────

def print_legal_warning():
    """Vypíš legálne upozornenie."""
    cprint("\n[bold red]⚠️  LEGÁLNE UPOZORNENIE[/bold red]")
    cprint("[dim]" + "=" * 50 + "[/dim]")
    cprint("[yellow]")
    cprint("  Tento nástroj používajte len na:")
    cprint("  • Vlastné testovacie siete (Faraday cage)")
    cprint("  • Vzdelávacie účely v izolovanom prostredí")
    cprint("  • Pasívny monitoring tam, kde to dovoľuje zákon")
    cprint("")
    cprint("  Odchyt GSM prevádzky bez súhlasu operátora")
    cprint("  môže byť trestný čin.")
    cprint("[/yellow]")
    cprint("[dim]" + "=" * 50 + "[/dim]\n")

def print_hardware_warnings(device: str):
    """Vypíš hardvérové upozornenia."""
    if device == "hackrf":
        cprint("\n[yellow]⚠️  HARDVÉROVÉ UPOZORNENIA PRE HackRF One:[/yellow]")
        cprint("  • Uistite sa, že HackRF má dostatočné napájanie")
        cprint("    (odporúčaný USB hub s vlastným napájaním)")
        cprint("  • Gain 40-45 dB je zvyčajne optimálny")
        cprint("  • Použite kvalitnú anténu pre lepšie výsledky")
        cprint("")

def main():
    ap = argparse.ArgumentParser(
        description="Automatický GSM skener + detektor šifrovania (headless)"
    )
    ap.add_argument("--band",
        choices=["GSM900", "EGSM900", "DCS1800", "GSM850", "all"],
        default="all",
        help="GSM pásmo na skenovanie")
    ap.add_argument("--gain", type=int, default=40,
        help="RF gain (default 40; HackRF odporúčam 40-45)")
    ap.add_argument("--scan-timeout", type=int, default=SCAN_TIMEOUT,
        help="Timeout pre skenovanie jedného pásma")
    ap.add_argument("--capture-time", type=int, default=CAPTURE_TIME,
        help="Čas na zachytenie šifrovania pre každú BTS")
    ap.add_argument("--output", type=str, default="gsm_results.json",
        help="Cesta pre JSON output")
    ap.add_argument("--scan-only", action="store_true",
        help="Len skenuj, nezachytávaj šifrovanie")
    ap.add_argument("--no-warning", action="store_true",
        help="Preskoč legálne upozornenie")
    
    args = ap.parse_args()

    # Úvod
    if RICH and console:
        console.print(Panel.fit(
            "[bold cyan]GSM Auto Scanner + Encryption Detector[/]\n"
            "[dim]RPi4 · HackRF One · headless · terminal mód[/dim]",
            border_style="cyan"
        ))
    else:
        print("=" * 50 + "\n GSM Auto Scanner – terminal mód\n" + "=" * 50)

    # Legálne upozornenie
    if not args.no_warning:
        print_legal_warning()
        input("Stlač ENTER pre pokračovanie (alebo Ctrl+C pre ukončenie)...")

    # 1. SDR zariadenie
    cprint("\n[bold]── 1. SDR zariadenie ──[/bold]")
    device = detect_device()
    
    if device == "none":
        cprint("[red]✗ Žiadne SDR zariadenie nenájdené![/red]")
        cprint("[dim]  Skontroluj USB kábel a udev pravidlá[/dim]")
        cprint("[dim]  Pre HackRF: sudo apt install hackrf[/dim]")
        sys.exit(1)
    
    print_hardware_warnings(device)
    
    if device == "uhd" and args.gain < 50:
        cprint("[yellow]  Tip: pre USRP odporúčam --gain 55[/yellow]")

    # 2. Skenovanie
    cprint("\n[bold]── 2. Skenovanie pásiem ──[/bold]")
    bands = BANDS_SK if args.band == "all" else [args.band]
    all_bts: List[BTSInfo] = []
    seen_arfcns = set()
    
    for band in bands:
        for b in run_scanner(band, args.gain, args.scan_timeout):
            if b.arfcn not in seen_arfcns:
                all_bts.append(b)
                seen_arfcns.add(b.arfcn)

    if not all_bts:
        cprint("\n[yellow]⚠ Žiadne BTS nenájdené.[/yellow]")
        cprint("[dim]  Skús: vyšší --gain | lepšia anténa | vonkajší priestor[/dim]")
        sys.exit(0)

    cprint(f"\n[green]✓ Nájdených [bold]{len(all_bts)}[/bold] BTS staníc[/green]")

    if args.scan_only:
        print_results(all_bts)
        save_json(all_bts, args.output)
        return

    # 3. Šifrovanie
    hcmd = find_headless()
    if not hcmd:
        cprint("\n[yellow]⚠ grgsm_livemon_headless / grgsm_decode nenájdené.[/yellow]")
        cprint("[dim]  sudo apt install gr-gsm[/dim]")
        cprint("[dim]  Alebo: https://github.com/ptrkrysik/gr-gsm[/dim]")
        print_results(all_bts)
        save_json(all_bts, args.output)
        return

    cprint(f"\n[bold]── 3. Zachytávanie šifrovania [{hcmd}] ──[/bold]")
    cprint(f"  [dim]{len(all_bts)} BTS × {args.capture_time}s[/dim]")
    cprint("  [yellow]⚠ POZNÁMKA: Cipher Mode sa zachytí len pri aktivite[/yellow]")
    cprint("  (registrácia, hovor, SMS na danej BTS)[/dim]")

    listener = CipherListener()
    stop_flag = threading.Event()
    listener.start()

    def on_sigint(sig, frame):
        cprint("\n[yellow]Prerušené – zobrazujem výsledky...[/yellow]")
        stop_flag.set()
    
    signal.signal(signal.SIGINT, on_sigint)

    try:
        for idx, bts in enumerate(all_bts):
            if stop_flag.is_set():
                break
            
            cprint(
                f"\n  [{idx + 1}/{len(all_bts)}] "
                f"[cyan]ARFCN {bts.arfcn}[/cyan] – "
                f"{bts.freq_mhz:.1f} MHz – {bts.operator}"
            )
            
            proc = start_capture(bts, args.gain)
            if proc is None:
                cprint("  [dim]→ Capture sa nespustil, preskakujem[/dim]")
                continue

            wait_with_progress(args.capture_time, stop_flag, bts.arfcn, listener)

            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

            with listener._lock:
                if bts.arfcn in listener.results:
                    bts.cipher = listener.results[bts.arfcn]
                    bts.cipher_detected_at = datetime.now().strftime("%H:%M:%S")
                else:
                    cprint("  [dim]→ Cipher Mode nezachytený (malo aktivity)[/dim]")
    
    finally:
        listener.stop()

    # 4. Výsledky
    cprint("\n[bold]── 4. Výsledky ──[/bold]")
    print_results(all_bts)
    save_json(all_bts, args.output)

    # Štatistiky
    counts = {k: 0 for k in CIPHER_MAP}
    unk = 0
    
    for b in all_bts:
        if b.cipher is None:
            unk += 1
        else:
            counts[b.cipher] = counts.get(b.cipher, 0) + 1

    cprint(
        f"\n[bold]Súhrn:[/bold]  "
        f"[bright_green]A5/3+: {counts[4] + counts[8]}[/bright_green]  |  "
        f"[yellow]A5/1: {counts[1]}[/yellow]  |  "
        f"[red]A5/0 (bez šifr.): {counts[0]}[/red]  |  "
        f"[dim]Nezistené: {unk}[/dim]"
    )
    
    cprint("\n[dim]📁 Výsledky uložené v: {args.output}[/dim]")

if __name__ == "__main__":
    main()
