import sys
import os
import pandas as pd

# Add current directory to path so we can import modules
sys.path.append(os.getcwd())

from modules.parser import LogParser
from modules.analyzer import LogAnalyzer

def verify():
    log_path = r"C:\Users\kiddp\Downloads\FORENSIC\Apache.log"
    print(f"Loading {log_path}...")
    
    parser = LogParser()
    df, errors = parser.parse_file(log_path)
    
    if df is None:
        print("Failed to parse log.")
        return

    print(f"Parsed {len(df)} rows.")
    
    analyzer = LogAnalyzer(df)
    
    # 1. Directory Traversal
    print("\n--- Testing Directory Traversal ---")
    dt = analyzer.detect_directory_traversal()
    print(f"Hits: {len(dt)}")
    if not dt.empty:
        print("Sample Hit:")
        print(dt.iloc[0][['ip', 'path']])
        
    # 2. Vuln Scanning
    print("\n--- Testing Vuln Scanning ---")
    vs = analyzer.detect_vuln_scanning()
    print(f"Hits: {len(vs)}")
    if not vs.empty:
        print("Sample Hit:")
        print(vs.iloc[0][['ip', 'path']])

    # 3. Risk Score Impact
    print("\n--- Testing Risk Scores ---")
    scores = analyzer.calculate_risk_score()
    
    # Check specific high risk IPs mentioned in plan
    target_ips = ['63.203.254.140', '210.22.201.118']
    for ip in target_ips:
        if ip in scores['ip'].values:
            row = scores[scores['ip'] == ip].iloc[0]
            print(f"IP: {ip} | Score: {row['risk_score']} | Severity: {row['severity']}")
        else:
            print(f"IP: {ip} not found in scores.")

if __name__ == "__main__":
    verify()
