"""
Cracking manager for WPA handshake cracking using aircrack-ng.
Provides start, progress monitoring, and stopping of cracking jobs.
"""
import subprocess
import time
import os
import re

class CrackManager:
    def __init__(self, db_manager, tmp_dir=None):
        self.db = db_manager
        self.tmp_dir = tmp_dir or os.getenv('TMPDIR', '/tmp')
        self.process = None
        self.handshake_file = None
        self.wordlist_file = None
        self.log_file = None
        self._log_fh = None

    def start(self, handshake_file, wordlist_file):
        """Start aircrack-ng on handshake_file using wordlist_file."""
        self.handshake_file = handshake_file
        self.wordlist_file = wordlist_file
        # prepare log file
        base = f"aircrack_{int(time.time())}"
        self.log_file = os.path.join(self.tmp_dir, f"{base}.log")
        try:
            self._log_fh = open(self.log_file, 'w+', encoding='utf-8', errors='ignore')
        except Exception:
            self._log_fh = None
        # build command
        cmd = ['aircrack-ng', '-w', self.wordlist_file, self.handshake_file]
        # start process
        try:
            if self._log_fh:
                self.process = subprocess.Popen(cmd, stdout=self._log_fh, stderr=self._log_fh)
            else:
                self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            self.process = None
            return False

    def progress(self):
        """Parse log file and return (attempts, total, key, done)."""
        attempts = 0
        total = 0
        key = None
        done = False
        if self.log_file and os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                # parse attempts and total
                m = re.search(r"Tested\s+(\d+)/(\d+)", content)
                if m:
                    attempts = int(m.group(1))
                    total = int(m.group(2))
                # parse key found
                km = re.search(r"KEY FOUND! \[\s*(.+?)\s*\]", content)
                if km:
                    key = km.group(1)
                # check if process finished
                if self.process and self.process.poll() is not None:
                    done = True
            except Exception:
                pass
        return attempts, total, key, done

    def stop(self):
        """Stop the cracking process."""
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                pass
        if self._log_fh:
            try:
                self._log_fh.flush()
                self._log_fh.close()
            except Exception:
                pass
        return True