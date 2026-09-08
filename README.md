Vulnerability Scanner

Network vulnerability scanner for Wi-Fi networks. Scans any IP address and any device within the local network.

Features:
- Scan any IP address in the network
- Detects vulnerabilities on all connected devices (routers, IoT, computers, smartphones)
- Supports multiple protocols
- GUI and command-line interface

Quick Start:
1. Install dependencies: pip install -r requirements.txt
2. Run GUI: python scanner_gui.py
3. Enter target IP and start scan

Files:
- scanner_engine.py - core scanning logic
- scanner_gui.py - graphical interface
- protocol_checks.py - vulnerability detection modules
- START_WINDOWS.bat - Windows launcher

Tests:
Run python test_scanner.py or python test_protocol_checks.py

Requirements:
- Python 3.7+
- Scapy, requests, tkinter

Use responsibly. Only scan networks you own or have permission to test.
