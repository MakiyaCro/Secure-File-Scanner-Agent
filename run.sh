#!/usr/bin/env bash
# ─── VulnScan Setup & Launcher ─────────────────────────────
set -e

GREEN='\033[0;32m'
AMBER='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗"
echo "  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║"
echo "  ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║"
echo "  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║"
echo "   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║"
echo "    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
echo -e "  LOCAL AI CODE SECURITY ANALYSIS // v2.4 // QWEN3${NC}"
echo ""

# ── Check Python ──────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}ERROR: python3 not found.${NC}"
  exit 1
fi

# ── Check Ollama ──────────────────────────────────────────────
echo -e "${AMBER}[*] Checking Ollama...${NC}"
if ! command -v ollama &>/dev/null; then
  echo -e "${RED}ERROR: Ollama not installed. Visit https://ollama.com${NC}"
  exit 1
fi

if ! curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo -e "${AMBER}[!] Ollama not running. Starting it...${NC}"
  ollama serve &>/dev/null &
  sleep 3
fi

# ── Check Qwen3 model ──────────────────────────────────────────
if ! ollama list 2>/dev/null | grep -q "qwen3.5:9b"; then
  echo -e "${AMBER}[!] qwen3.5:9b model not found. Pulling...${NC}"
  echo -e "${AMBER}    This may take several minutes depending on connection speed.${NC}"
  ollama pull qwen3.5:9b
fi
echo -e "${GREEN}[✓] Qwen3.5:9b model ready.${NC}"

# ── Python venv ───────────────────────────────────────────────
if [ ! -d "venv" ]; then
  echo -e "${AMBER}[*] Creating virtual environment...${NC}"
  python3 -m venv venv
fi
source venv/bin/activate

echo -e "${AMBER}[*] Installing dependencies...${NC}"
pip install -q -r requirements.txt

echo ""
echo -e "${GREEN}[✓] All systems ready.${NC}"
echo -e "${GREEN}[*] Starting VulnScan on http://127.0.0.1:5000${NC}"
echo -e "${AMBER}    Press Ctrl+C to stop.${NC}"
echo ""

python3 app.py