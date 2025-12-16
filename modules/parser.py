import re
import pandas as pd
from datetime import datetime

class LogParser:
    def __init__(self):
        # Combined Log Format Regex
        self.access_pattern = re.compile(
            r'^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+)\s*(\S+)?\s*" (\d{3}) (\S+) "((?:[^"]|\\")*)" "((?:[^"]|\\")*)"'
        )
        # Apache Error Log Regex: [Sun Dec 04 04:47:44 2005] [error] [client 1.2.3.4] Message...
        self.error_pattern = re.compile(
            r'^\[([^\]]+)\] \[([^\]]+)\] (?:\[client ([^\]]+)\] )?(.*)$'
        )
        # Syslog Regex (RFC 3164ish): Mar 23 00:09:01 webserver CRON[23891]: ...
        # (Month Day Time) (Hostname) (Process): (Message)
        # Syslog Regex (RFC 3164ish): Mar 23 00:09:01 webserver CRON[23891]: ...
        # (Month Day Time) (Hostname) (Process): (Message)
        self.syslog_pattern = re.compile(
            r'^([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s(\S+)\s([^:]+):\s(.*)$'
        )
        # Suricata fast.log
        # Regex adjusted for timestamps with colons and general robustness
        self.suricata_pattern = re.compile(
            r'^(\S+)\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]\s+\[Classification:\s+(.+?)\]\s+\[Priority:\s+(\d+)\]\s+\{(.+?)\}\s+(\S+):(\d+)\s+->\s+(\S+):(\d+)'
        )

    def try_parse_structured(self, file_path):
        # CSV
        if file_path.lower().endswith('.csv'):
            try:
                df = pd.read_csv(file_path)
                rename_map = {
                    'IP_Address': 'ip', 'Timestamp': 'timestamp', 'Activity_Type': 'method',
                    'Resource_Accessed': 'path', 'File_Size': 'size', 'Label': 'status_label',
                    'User_Agent': 'user_agent'
                }
                df.rename(columns=rename_map, inplace=True)
                self._normalize_columns(df)
                return df, 0
            except: pass
            
        # JSON
        if file_path.lower().endswith(('.json', '.jsonl', '.log')):
            try:
                try: df = pd.read_json(file_path, lines=True)
                except: df = pd.read_json(file_path)
                
                if not df.empty:
                    rename_map = {
                        'ip_address': 'ip', 'client_ip': 'ip', 'remote_addr': 'ip',
                        '@timestamp': 'timestamp', 'time': 'timestamp', 'date': 'timestamp',
                        'request_method': 'method', 'verb': 'method',
                        'request_uri': 'path', 'url': 'path', 'request': 'path',
                        'status_code': 'status', 'response_code': 'status',
                        'body_bytes_sent': 'size', 'bytes': 'size',
                        'http_referer': 'referrer', 'referer': 'referrer',
                        'http_user_agent': 'user_agent', 'agent': 'user_agent',
                        'message': 'path'
                    }
                    df.rename(columns=rename_map, inplace=True)
                    if 'timestamp' in df.columns or 'message' in df.columns:
                        self._normalize_columns(df)
                        return df, 0
            except: pass
        return None, 0

    def _normalize_columns(self, df):
        required_cols = ['ip', 'timestamp', 'method', 'path', 'protocol', 'status', 'size', 'referrer', 'user_agent', 'type']
        for col in required_cols:
            if col not in df.columns:
                df[col] = 0 if col == 'size' or col == 'status' else '-'

    def parse_file(self, file_path):
        """
        Parses a log file and returns a DataFrame and error count.
        """
        # 1. Structured
        df, errors = self.try_parse_structured(file_path)
        if df is not None: return df, errors

        # 2. Unstructured Regex
        data = []
        errors = 0
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue

                    # Access Log
                    match = self.access_pattern.match(line)
                    if match:
                        g = match.groups()
                        data.append({
                            "ip": g[0], "timestamp": self.parse_timestamp(g[3]), "method": g[5],
                            "path": g[6], "protocol": g[7], "status": int(g[8]),
                            "size": int(g[9]) if g[9] != '-' else 0,
                            "referrer": g[10], "user_agent": g[11], "type": "access"
                        })
                        continue

                    # Error Log
                    match = self.error_pattern.match(line)
                    if match:
                        g = match.groups()
                        data.append({
                            "ip": g[2] if g[2] else "0.0.0.0", "timestamp": self.parse_timestamp(g[0]),
                            "method": "ERROR", "path": g[3], "protocol": "UNKNOWN", "status": 0,
                            "size": 0, "referrer": "-", "user_agent": "-", "type": "error"
                        })
                        continue

                    # Suricata
                    match = self.suricata_pattern.match(line)
                    if match:
                        g = match.groups()
                        data.append({
                            "ip": g[6], "timestamp": g[0], "method": "IDS",
                            "path": f"{g[2]} [Class: {g[3]}] [Pri: {g[4]}]", "protocol": g[5], "status": 0,
                            "size": 0, "referrer": f"Dst: {g[8]}:{g[9]}", "user_agent": "Suricata", "type": "suricata"
                        })
                        continue

                    # Syslog
                    match = self.syslog_pattern.match(line)
                    if match:
                        g = match.groups()
                        # Extract IP from message if possible (support 'from' and 'rhost=')
                        # rhost=192.168.1.1 or from 192.168.1.1
                        ip_match = re.search(r'(?:from|rhost=)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', g[3])
                        ip = ip_match.group(1) if ip_match else "0.0.0.0"
                        
                        data.append({
                            "ip": ip, "timestamp": g[0], "method": "SYSLOG",
                            "path": g[3], "protocol": g[2], "status": 0,
                            "size": 0, "referrer": "-", "user_agent": "-", "type": "syslog"
                        })
                        continue

                    errors += 1
            
            df = pd.DataFrame(data)
            return df, errors
        except Exception as e:
            print(f"Error parsing file: {e}")
            return None, 0

    def parse_timestamp(self, ts_str):
        """Helper to parse log timestamp to datetime object if needed."""
        # Example: 10/Oct/2000:13:55:36 -0700
        try:
            return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                # Syslog format: Mar 23 00:09:01
                # Note: No year in standard syslog, assume current year or handle separately
                return datetime.strptime(ts_str, "%b %d %H:%M:%S")
            except ValueError:
                return None
