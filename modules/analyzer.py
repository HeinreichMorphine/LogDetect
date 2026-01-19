import pandas as pd

import json
import urllib.request
import time
import os

class LogAnalyzer:
    # Static list of Known Bad IPs (IOCs)
    KNOWN_BAD_IPS = [
        "192.168.1.5", "10.10.10.10", "45.33.32.156", "185.220.101.43" 
    ]
    
    # Whitelist (Benign IPs to ignore in anomaly checks)
    WHITELIST_IPS = [
        "127.0.0.1", "::1", "0.0.0.0", "localhost"
    ]

    CACHE_FILE = "geo_cache.json"

    def __init__(self, dataframe):
        self.df = dataframe
        # Load Cache from Disk
        self.geo_cache = self.load_cache()

    def load_cache(self):
        try:
            if os.path.exists(self.CACHE_FILE):
                with open(self.CACHE_FILE, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def save_cache(self):
        try:
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(self.geo_cache, f)
        except Exception as e:
            print(f"Cache save failed: {e}")

    def detect_high_volume_ips(self, threshold=100):
        """Identify IPs with request counts exceeding the threshold (Excluding Whitelist)."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        # Filter out whitelisted IPs first
        clean_df = self.df[~self.df['ip'].isin(self.WHITELIST_IPS)]
        
        if clean_df.empty:
            return pd.DataFrame()
            
        ip_counts = clean_df['ip'].value_counts().reset_index()
        ip_counts.columns = ['ip', 'count']
        return ip_counts[ip_counts['count'] > threshold]

    def get_traffic_summary(self):
        """Return general traffic statistics."""
        if self.df is None or self.df.empty:
            return {}
            
        total = len(self.df)
        success = len(self.df[(self.df['status'] >= 200) & (self.df['status'] < 400)])
        errors = len(self.df[self.df['status'] >= 400])
        
        return {
            "Total Requests": total,
            "Successful (Normal)": success,
            "Failed/Error": errors
        }

    def analyze_status_codes(self):
        """Return counts of 4xx and 5xx errors."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()

        # Filter for 400-599
        errors = self.df[(self.df['status'] >= 400) & (self.df['status'] < 600)]
        error_counts = errors['status'].value_counts().reset_index()
        error_counts.columns = ['status', 'count']
        return error_counts

    def _escape_regex(self, s):
        import re
        return re.escape(s)

    def get_geolocation(self, ip):
        """
        Fetch IP geolocation from public API (ip-api.com) with Disk Caching.
        """
        # Skip local/private IPs to save API calls
        if ip.startswith(('192.168.', '10.', '127.', '172.16.', '0.0.0.0')):
            return ("Local Network", "Private")
            
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        try:
            # Rate limit mitigation for free API (max 45/min)
            time.sleep(0.5) 
            url = f"http://ip-api.com/json/{ip}?fields=country,isp"
            with urllib.request.urlopen(url, timeout=3) as response:
                data = json.loads(response.read().decode())
                country = data.get('country', "Unknown")
                isp = data.get('isp', "Unknown")
                
                self.geo_cache[ip] = (country, isp)
                return country, isp
        except Exception:
            return ("Lookup Failed", "N/A")

    def detect_directory_traversal(self):
        """Identify Directory Traversal attempts."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        # Common traversal patterns (URL encoded and raw)
        patterns = [
            r'\.\.%5c', r'\.\.%c0%af', r'\.\.%252e', r'\.\./', r'\.\.\\'
        ]
        
        # Vectorized check
        # Escape just in case, though these are mostly regex safe chars or already escaped
        joined_patterns = '|'.join(patterns)
        
        mask = self.df['path'].astype(str).str.contains(joined_patterns, case=False, regex=True)
        traversal_hits = self.df[mask]
        
        return traversal_hits[['timestamp', 'ip', 'method', 'path', 'status']]

    def detect_vuln_scanning(self):
        """Identify scanning for known vulnerable scripts/files."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
            
        target_files = [
            r'root\.exe', r'msadc', r'_vti_bin', r'awstats\.pl', r'openwebmail', 
            r'cmd\.exe', r'/cgi-bin/', r'\.php'
        ]
        
        # Vectorized check
        joined_targets = '|'.join(target_files)
        
        mask = self.df['path'].astype(str).str.contains(joined_targets, case=False, regex=True)
        scan_hits = self.df[mask]
        
        return scan_hits[['timestamp', 'ip', 'method', 'path', 'status']]

    def calculate_risk_score(self):
        """
        Calculate a risk score for each IP address.
        Focuses ONLY on: Status Codes, IOCs, Directory Traversal, Vuln Scanning.
        """
        if self.df is None or self.df.empty:
            return pd.DataFrame()

        # Initialize score
        scores = self.df.groupby('ip').size().reset_index(name='request_count')
        scores['risk_score'] = 0

        # Factor 1: 4xx Errors (Weight 1)
        errors_4xx = self.df[(self.df['status'] >= 400) & (self.df['status'] < 500)].groupby('ip').size()
        scores['risk_score'] += scores['ip'].map(errors_4xx).fillna(0) * 1

        # Factor 2: 5xx Errors (Weight 2)
        errors_5xx = self.df[self.df['status'] >= 500].groupby('ip').size()
        scores['risk_score'] += scores['ip'].map(errors_5xx).fillna(0) * 2

        # Factor 3: Known Bad IPs / IOCs (Weight 50) - CRITICAL
        scores['ioc_match'] = scores['ip'].apply(lambda x: "YES" if x in self.KNOWN_BAD_IPS else "NO")
        scores.loc[scores['ioc_match'] == "YES", 'risk_score'] += 50
        
        # Factor 4: Directory Traversal (Weight 30) - HIGH/CRITICAL
        dt_hits = self.detect_directory_traversal()
        if not dt_hits.empty:
            dt_ip_counts = dt_hits.groupby('ip').size()
            scores['risk_score'] += scores['ip'].map(dt_ip_counts).fillna(0) * 30

        # Factor 5: Vuln Scanning (Weight 10)
        vs_hits = self.detect_vuln_scanning()
        if not vs_hits.empty:
            vs_ip_counts = vs_hits.groupby('ip').size()
            scores['risk_score'] += scores['ip'].map(vs_ip_counts).fillna(0) * 10

        # Assign Severity Label
        def get_label(score):
            if score > 100: return 'CRITICAL'
            if score > 50: return 'HIGH'
            if score > 20: return 'MEDIUM'
            if score > 0: return 'LOW'
            return 'NORMAL'

        scores['severity'] = scores['risk_score'].apply(get_label)
        
        # New: Geolocation Fetching for High Risk IPs (Top 5 optimization for Dashboard)
        scores['country'] = "Pending"
        scores['isp'] = "Pending"
        
        # Sort by risk score descending
        sorted_scores = scores.sort_values('risk_score', ascending=False)
        
        # Filter for logic
        high_risk_mask = sorted_scores['severity'].isin(['CRITICAL', 'HIGH'])
        
        # Take top 5 unique IPs from high risk
        top_risk_ips = sorted_scores[high_risk_mask].head(5)
        
        # Iterate only through top risk ones
        for index, row in top_risk_ips.iterrows():
            country, isp = self.get_geolocation(row['ip'])
            scores.at[index, 'country'] = country
            scores.at[index, 'isp'] = isp
            
        # Threshold Filter for Report Clarity (Reduce Noise)
        filtered_scores = scores[
            (scores['risk_score'] >= 10) | 
            (scores['request_count'] >= 50)
        ]
            
        return filtered_scores.sort_values('risk_score', ascending=False)
