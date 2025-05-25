"""
Database manager for WiFi Marauder app.
Provides methods for logging scans, captures, deauths, anonymity logs,
decoy activities, cracks, EvilAP, and FakeAuth events.
"""
import sqlite3
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_file="wifi_marauder.db"):
        self.conn = sqlite3.connect(db_file)
        self.create_tables()

    def create_tables(self):
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
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deauths (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                bssid TEXT,
                client TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anonymity_logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                feature TEXT,
                status TEXT,
                details TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS decoy_activities (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                type TEXT,
                details TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cracks (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                handshake_file TEXT,
                wordlist_file TEXT,
                status TEXT,
                key_found TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evilaps (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                essid TEXT,
                password TEXT,
                status TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fakeauths (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                bssid TEXT,
                client TEXT,
                status TEXT
            )
        ''')
        self.conn.commit()

    def insert_scan(self, interface, duration, output):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO scans (timestamp, interface, duration, output) VALUES (?, ?, ?, ?)",
            (timestamp, interface, duration, output)
        )
        self.conn.commit()
        return cursor.lastrowid

    def insert_capture(self, scan_id, bssid, essid, handshake):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO captures (scan_id, bssid, essid, handshake) VALUES (?, ?, ?, ?)",
            (scan_id, bssid, essid, handshake)
        )
        self.conn.commit()

    def insert_deauth(self, scan_id, bssid, client):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO deauths (scan_id, bssid, client, timestamp) VALUES (?, ?, ?, ?)",
            (scan_id, bssid, client, timestamp)
        )
        self.conn.commit()

    def insert_anonymity_log(self, feature, status, details):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO anonymity_logs (timestamp, feature, status, details) VALUES (?, ?, ?, ?)",
            (timestamp, feature, status, details)
        )
        self.conn.commit()

    def insert_decoy_activity(self, activity_type, details):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO decoy_activities (timestamp, type, details) VALUES (?, ?, ?)",
            (timestamp, activity_type, details)
        )
        self.conn.commit()

    def insert_crack(self, handshake_file, wordlist_file, status, key_found):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO cracks (timestamp, handshake_file, wordlist_file, status, key_found) VALUES (?, ?, ?, ?, ?)",
            (timestamp, handshake_file, wordlist_file, status, key_found)
        )
        self.conn.commit()
        return cursor.lastrowid

    def insert_evilap(self, essid, password, status):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO evilaps (timestamp, essid, password, status) VALUES (?, ?, ?, ?)",
            (timestamp, essid, password, status)
        )
        self.conn.commit()
        return cursor.lastrowid

    def insert_fakeauth(self, bssid, client, status):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO fakeauths (timestamp, bssid, client, status) VALUES (?, ?, ?, ?)",
            (timestamp, bssid, client, status)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_scan_logs(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
        return cursor.fetchall()

    def get_captures_for_scan(self, scan_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM captures WHERE scan_id = ?", (scan_id,))
        return cursor.fetchall()

    def get_deauths_for_scan(self, scan_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM deauths WHERE scan_id = ? ORDER BY timestamp", (scan_id,))
        return cursor.fetchall()

    def get_all_captures(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM captures")
        return cursor.fetchall()

    def get_all_deauths(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM deauths")
        return cursor.fetchall()

    def get_all_decoy_activities(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM decoy_activities")
        return cursor.fetchall()

    def get_all_cracks(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cracks")
        return cursor.fetchall()

    def get_all_evilaps(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM evilaps")
        return cursor.fetchall()

    def get_all_fakeauths(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM fakeauths")
        return cursor.fetchall()

    def close(self):
        self.conn.close()