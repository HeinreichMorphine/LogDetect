import pandas as pd

class LogAnalyzer:
    def __init__(self, dataframe):
        self.df = dataframe

    def detect_high_volume_ips(self, threshold=100):
        """Identify IPs with request counts exceeding the threshold."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        ip_counts = self.df['ip'].value_counts().reset_index()
        ip_counts.columns = ['ip', 'count']
        return ip_counts[ip_counts['count'] > threshold]

    def detect_forbidden_files(self, extensions=None):
        """Identify requests for sensitive file types."""
        if extensions is None:
            extensions = ['.env', '.sql', '.bak', '.config', '.git', '.htpasswd']
        
        if self.df is None or self.df.empty:
            return pd.DataFrame()

        # Helper to check extension
        def has_forbidden_ext(path):
            return any(path.endswith(ext) for ext in extensions)

        forbidden_hits = self.df[self.df['path'].apply(has_forbidden_ext)]
        return forbidden_hits[['timestamp', 'ip', 'method', 'path', 'status']]

    def analyze_status_codes(self):
        """Return counts of 4xx and 5xx errors."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()

        # Filter for 400-599
        errors = self.df[(self.df['status'] >= 400) & (self.df['status'] < 600)]
        error_counts = errors['status'].value_counts().reset_index()
        error_counts.columns = ['status', 'count']
        return error_counts

    def detect_suspicious_user_agents(self, signatures=None):
        """Identify requests with known suspicious user agent strings."""
        if signatures is None:
            signatures = ['sqlmap', 'nikto', 'nmap', 'python-requests', 'curl', 'wget', 'wpscan', 'dirb', 'gobuster', 'hydra']
        
        if self.df is None or self.df.empty:
            return pd.DataFrame()

        def is_suspicious(ua):
            if not isinstance(ua, str): return False
            return any(sig.lower() in ua.lower() for sig in signatures)

        suspicious_hits = self.df[self.df['user_agent'].apply(is_suspicious)]
        return suspicious_hits[['timestamp', 'ip', 'user_agent', 'path']]

    def detect_large_responses(self, threshold_bytes=1000000): # 1MB default
        """Identify responses with unusually large sizes (potential exfiltration)."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
            
        large_hits = self.df[self.df['size'] > threshold_bytes]
        return large_hits[['timestamp', 'ip', 'method', 'path', 'status', 'size']]

    def detect_brute_force(self, threshold=5):
        """Identify IPs with high counts of failed login attempts (401/403 or textual failures)."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
            
        # 1. HTTP Status Code Failures (401, 403)
        status_failures = self.df[self.df['status'].isin([401, 403])]
        
        # 2. Textual/Syslog Failures (Status == 0)
        syslog_failures = pd.DataFrame()
        if 'path' in self.df.columns:
            # Common SSH/Auth failure patterns
            pattern = r'failed password|authentication failure|invalid user'
            # Filter where status is 0 (Syslog/Error) AND path matches pattern
            syslog_failures = self.df[
                (self.df['status'] == 0) & 
                (self.df['path'].astype(str).str.contains(pattern, case=False, regex=True))
            ]

        # Combine
        all_failures = pd.concat([status_failures, syslog_failures])

        if all_failures.empty:
            return pd.DataFrame()
            
        # Group by IP
        counts = all_failures['ip'].value_counts().reset_index()
        counts.columns = ['ip', 'count']
        
        # Filter by threshold
        suspects = counts[counts['count'] > threshold]
        return suspects

    def get_traffic_summary(self):
        """Return general traffic statistics (Benign vs Errors)."""
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

    def detect_ids_alerts(self):
        """Identify Suricata/IDS specific alert rows."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        if 'type' not in self.df.columns:
            return pd.DataFrame()
            
        # Filter for rows where type is 'suricata' (or method is 'IDS')
        ids_alerts = self.df[self.df['type'] == 'suricata']
        
        if ids_alerts.empty:
            return pd.DataFrame()
            
        # Return summary of alerts
        # Count by path (alert message) and IP
        alerts_summary = ids_alerts.groupby(['ip', 'path']).size().reset_index(name='count')
        return alerts_summary
