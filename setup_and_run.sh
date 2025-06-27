#!/bin/bash
echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "[*] Installing dependencies..."
pip install --upgrade pip
pip install fastapi uvicorn flask pyshark watchdog cryptography
pip install pyvis networkx
echo "[*] Installing system tools (MDK4, aircrack-ng, kismet, reaver, etc.)..."
python3 install_tools.py || echo "[!] Some tools may not have installed correctly. Please review the output above."

echo "[*] To run the toolkit:"
echo "source venv/bin/activate && ./run_gui.sh"