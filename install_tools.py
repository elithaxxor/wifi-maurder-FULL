#!/usr/bin/env python3

import os
import platform
import subprocess
import sys

def run_command(command, error_message="Error occurred"):
    """Run a shell command and handle potential errors."""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        print(f"Success: {result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{error_message}: {e.stderr}")
        return False

def install_linux_tools():
    """Install tools on Linux systems."""
    print("Detected Linux system. Installing tools using apt-get...")
    commands = [
        ("sudo apt-get update", "Failed to update package list"),
        ("sudo apt-get install -y aircrack-ng", "Failed to install aircrack-ng"),
        ("sudo apt-get install -y hostapd", "Failed to install hostapd"),
        ("sudo apt-get install -y bluez", "Failed to install bluez for Bluetooth tools"),
        ("sudo apt-get install -y mdk4", "Failed to install mdk4"),
        ("sudo apt-get install -y kismet", "Failed to install kismet"),
        ("sudo apt-get install -y reaver", "Failed to install reaver/wash for WPS testing"),
        ("sudo apt-get install -y ettercap-text-only", "Failed to install ettercap for ARP poisoning"),
        ("sudo apt-get install -y tcpdump", "Failed to install tcpdump"),
        ("sudo apt-get install -y netcat", "Failed to install netcat"),
        ("sudo apt-get install -y dnschef", "Failed to install dnschef for DNS spoofing"),
        ("sudo apt-get install -y mitmproxy", "Failed to install mitmproxy for HTTP proxy attacks"),
        ("sudo apt-get install -y nmap", "Failed to install nmap for network scanning"),
        ("sudo apt-get install -y metasploit-framework", "Failed to install Metasploit Framework"),
        ("sudo apt-get install -y zaproxy", "Failed to install OWASP ZAP (zaproxy)"),
        ("sudo apt-get install -y wireshark", "Failed to install Wireshark")
    ]
    
    for cmd, err_msg in commands:
        if not run_command(cmd, err_msg):
            return False
    # Install RouterSploit via pip
    pip_cmd = f"{sys.executable} -m pip install routersploit"
    if not run_command(pip_cmd, "Failed to install RouterSploit"):  
        print("Warning: RouterSploit installation failed.")
    return True

def install_macos_tools():
    """Install tools on macOS systems using Homebrew."""
    print("Detected macOS system. Installing tools using Homebrew...")
    if not run_command("brew -v", "Homebrew not installed"):
        print("Please install Homebrew first from https://brew.sh")
        return False
    
    commands = [
        ("brew install aircrack-ng", "Failed to install aircrack-ng"),
        ("brew install kismet", "Failed to install kismet"),
        ("brew install reaver", "Failed to install reaver for WPS testing"),
        ("brew install wash || echo 'wash may be included with reaver or installed separately'", "Failed to install wash for WPS"),
        ("brew install ettercap", "Failed to install ettercap for ARP poisoning"),
        ("brew install tcpdump", "Failed to install tcpdump"),
        ("brew install netcat", "Failed to install netcat"),
        ("brew install dnschef || pip3 install dnschef", "Failed to install dnschef for DNS spoofing"),
        ("brew install mitmproxy", "Failed to install mitmproxy for HTTP proxy attacks"),
        ("brew install nmap", "Failed to install nmap for network scanning"),
        ("brew install zaproxy", "Failed to install OWASP ZAP"),
        ("brew install metasploit", "Failed to install Metasploit Framework"),
        ("brew install wireshark", "Failed to install Wireshark"),
        ("brew install mdk4 || echo 'mdk4 not available in Homebrew, install manually'", "Failed to install mdk4")
    ]
    
    success = True
    for cmd, err_msg in commands:
        if not run_command(cmd, err_msg):
            success = False
            print(f"Note: If {cmd.split()[1]} is not available in Homebrew, you may need to install it manually.")
    
    print("Note: 'hostapd' is not available in Homebrew. You may need to install it manually or use Linux for full WiFi flooding feature.")
    # Install RouterSploit via pip
    pip_cmd = f"{sys.executable} -m pip install routersploit"
    if not run_command(pip_cmd, "Failed to install RouterSploit"):  
        print("Warning: RouterSploit installation failed.")
    return success

def main():
    """Main function to detect OS and install appropriate tools."""
    system = platform.system()
    print(f"Starting WiFi Marauder tools installation on {system}...")
    
    if system == "Linux":
        success = install_linux_tools()
    elif system == "Darwin":  # macOS
        success = install_macos_tools()
    else:
        print(f"Unsupported OS: {system}. This script supports Linux and macOS only.")
        return 1
    
    if success:
        print("All available tools installed successfully! You may still need to install some tools manually.")
        print("Note: Some tools may require additional configuration or kernel modules for full functionality.")
        return 0
    else:
        print("Installation failed for one or more tools or they are not available in the package manager.")
        print("Please check the error messages above and follow manual installation instructions if needed.")
        print("You may need to install some tools manually or ensure you have the necessary permissions.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
