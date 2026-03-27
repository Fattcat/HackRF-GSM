#!/bin/bash
# ============================================================
# GSM Scanner – setup pre Raspberry Pi 4 + HackRF One
# Spusti: chmod +x setup.sh && ./setup.sh
#
# ⚠️ POZNÁMKA: Tento skript inštaluje nástroje pre GSM analýzu.
#    Používaj len na legálne účely (vlastné siete, vzdelávanie).
# ============================================================

set -e

echo "=== GSM Auto Scanner – Setup pre RPi4 + HackRF One ==="
echo ""

# Farby pre output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Systémové závislosti
echo -e "${GREEN}[1/5]${NC} Inštalácia systémových balíkov..."

sudo apt install -y \
    python3 python3-pip python3-venv \
    git cmake build-essential \
    gr-osmosdr libosmosdr-dev \
    hackrf libhackrf-dev \
    wireshark-common libwireshark-dev \
    libusb-1.0-0-dev \
    2>/dev/null || true

# 2. gr-gsm kontrola
echo -e "${GREEN}[2/5]${NC} Kontrola gr-gsm..."

if command -v grgsm_scanner &> /dev/null; then
    echo -e "  ${GREEN}✓ gr-gsm už je nainštalované${NC}"
    GRGSM_VERSION=$(grgsm_scanner --help 2>&1 | head -1 || echo "neznáma")
    echo -e "  [dim]Verzia: $GRGSM_VERSION[/dim]"
else
    echo -e "  ${YELLOW}⚠ gr-gsm nenájdené${NC}"
    echo ""
    echo "  Odporúčam nainštalovať zo zdroja (aktuálnejšia verzia):"
    echo ""
    echo "  git clone https://github.com/ptrkrysik/gr-gsm.git"
    echo "  cd gr-gsm"
    echo "  mkdir build && cd build"
    echo "  cmake .."
    echo "  make -j4"
    echo "  sudo make install"
    echo "  sudo ldconfig"
    echo ""
    read -p "Chceš pokračovať bez gr-gsm? (skript bude obmedzený) [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Ukončujem setup. Nainštaluj gr-gsm a spusti znova."
        exit 1
    fi
fi

# 3. Python venv
echo -e "${GREEN}[3/5]${NC} Vytváram Python virtual environment..."

if [ -d "venv" ]; then
    echo "  [dim]venv už existuje, preskakujem${NC}"
else
    python3 -m venv venv
    echo "  ${GREEN}✓ venv vytvorený${NC}"
fi

source venv/bin/activate

# 4. Python balíky
echo -e "${GREEN}[4/5]${NC} Inštalácia Python balíkov..."
pip install --upgrade pip -q
pip install rich -q
echo "  ${GREEN}✓ rich nainštalovaný${NC}"

# 5. Udev pravidlá pre HackRF
echo -e "${GREEN}[5/5]${NC} Konfigurácia udev pravidiel pre HackRF..."

if [ -f /etc/udev/rules.d/52-hackrf.rules ]; then
    echo "  [dim]Udev pravidlá už existujú${NC}"
else
    echo "  Vytváram udev pravidlá..."
    echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6089", MODE="0666", GROUP="plugdev"' | sudo tee /etc/udev/rules.d/52-hackrf.rules > /dev/null
    sudo udevadm control --reload-rules
    sudo udevadm trigger
    echo "  ${GREEN}✓ Udev pravidlá vytvorené${NC}"
fi

# Konfigurácia gr-gsm pre venv (ak je systémový)
echo ""
echo -e "${GREEN}[BONUS]${NC} Konfigurácia gr-gsm pre venv..."

GRGSM_PATH=$(python3 -c "import sys; paths=[p for p in sys.path if 'dist-packages' in p or 'site-packages' in p]; print(paths[0] if paths else '')" 2>/dev/null || echo "")

if [ -n "$GRGSM_PATH" ]; then
    VENV_SITE=$(venv/bin/python -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "")
    if [ -n "$VENV_SITE" ]; then
        echo "$GRGSM_PATH" > "$VENV_SITE/grgsm_system.pth"
        echo "  ${GREEN}✓ gr-gsm path: $GRGSM_PATH → $VENV_SITE/grgsm_system.pth${NC}"
    fi
fi

# Záver
echo ""
echo "=== Setup dokončený ==="
echo ""
echo -e "${GREEN}Ďalšie kroky:${NC}"
echo ""
echo "  1. Odpoj a pripoj HackRF One (alebo reštartuj RPi)"
echo "  2. Over pripojenie: hackrf_info"
echo "  3. Aktivuj venv: source venv/bin/activate"
echo "  4. Spusti scanner: sudo python3 gsm_auto_scanner.py --help"
echo ""
echo -e "${YELLOW}⚠️ DÔLEŽITÉ:${NC}"
echo "  • sudo je potrebné pre prístup k SDR zariadeniu"
echo "  • Pre lepšiu stabilitu použi USB hub s vlastným napájaním"
echo "  • Gain 40-45 dB je optimálny pre HackRF One"
echo ""
echo -e "${RED}⚖️ LEGÁLNE UPOZORNENIE:${NC}"
echo "  Používaj tento nástroj len na vlastné siete alebo"
echo "  v izolovanom prostredí (Faraday cage). Odchyt GSM"
echo "  prevádzky bez súhlasu operátora môže byť nelegálny."
echo ""
