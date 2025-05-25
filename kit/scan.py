"""
Scan manager for WiFi Marauder using airodump-ng.
"""
import subprocess
import time
import os
import csv
import json

class ScanManager:
    def __init__(self, db_manager, tmp_dir=None):
        self.db = db_manager
        self.tmp_dir = tmp_dir or os.getenv('TMPDIR', '/tmp')
        self.process = None
        self.csv_base = None
        self.start_time = None
        self.duration = None
        self.interface = None
        self.log_file = None
        self._log_fh = None

    def start(self, interface, duration):
        """Start airodump-ng scan on interface for duration seconds."""
        base = f"wifi_scan_{int(time.time())}"
        self.csv_base = os.path.join(self.tmp_dir, base)
        # Clean up old CSVs
        for f in os.listdir(self.tmp_dir):
            if f.startswith(base) and f.endswith('.csv'):
                try:
                    os.remove(os.path.join(self.tmp_dir, f))
                except:
                    pass
        # Prepare log file for raw output
        self.log_file = self.csv_base + '.log'
        try:
            self._log_fh = open(self.log_file, 'w+', encoding='utf-8', errors='ignore')
        except Exception:
            self._log_fh = None
        # Start process capturing stdout and stderr to log file if possible
        cmd = ["airodump-ng", "--write", self.csv_base, "--output-format", "csv", interface]
        try:
            if self._log_fh:
                self.process = subprocess.Popen(cmd, stdout=self._log_fh, stderr=subprocess.STDOUT)
            else:
                self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            self.process = None
            return False
        self.interface = interface
        self.start_time = time.time()
        self.duration = duration
        return True

    def progress(self):
        """Return elapsed time and percentage done."""
        if not self.start_time or not self.duration:
            return 0, 0
        elapsed = time.time() - self.start_time
        pct = min(100, int(elapsed / self.duration * 100))
        return elapsed, pct

    def stop(self):
        """Stop the scanning process."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                pass
        # Close log file handler
        if self._log_fh:
            try:
                self._log_fh.flush()
                self._log_fh.close()
            except Exception:
                pass
        return True

    def parse_results(self):
        """Parse the generated CSV and return list of networks."""
        networks = []
        # No scan has been started
        if not self.csv_base:
            return networks
        base = os.path.basename(self.csv_base)
        csv_file = None
        for f in os.listdir(self.tmp_dir):
            if f.startswith(base) and f.endswith('.csv'):
                csv_file = os.path.join(self.tmp_dir, f)
                break
        if not csv_file:
            return networks
        try:
            with open(csv_file, newline='', encoding='utf-8', errors='ignore') as csvf:
                reader = csv.reader(csvf)
                for row in reader:
                    if len(row) >= 14 and row[0] and ':' in row[0] and row[13].strip():
                        networks.append({
                            'bssid': row[0].strip(),
                            'essid': row[13].strip(),
                            'signal': row[8].strip(),
                            'channel': row[3].strip(),
                            'encryption': row[5].strip()
                        })
        except Exception:
            pass
        return networks

    def record(self, interface):
        """Insert the last scan results into the database."""
        nets = self.parse_results()
        # Record scan results to DB, using 0 if duration not set
        try:
            output = json.dumps(nets)
            duration = int(self.duration) if self.duration else 0
            self.db.insert_scan(interface, duration, output)
        except Exception:
            pass
        return nets