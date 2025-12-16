import sys
import os
import pandas as pd
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.parser import LogParser

def verify_json_support():
    parser = LogParser()
    
    # Create a dummy JSON log file
    dummy_log = [
        {"timestamp": "2024-10-12T10:00:00", "client_ip": "192.168.1.100", "verb": "GET", "url": "/login", "status_code": 200, "message": "Login success"},
        {"timestamp": "2024-10-12T10:05:00", "client_ip": "10.0.0.5", "verb": "POST", "url": "/admin", "status_code": 403, "message": "Access denied"}
    ]
    
    file_path = "tests/dummy_log.json"
    
    # Write as JSON Lines
    with open(file_path, 'w') as f:
        for entry in dummy_log:
            f.write(json.dumps(entry) + "\n")
            
    print(f"Created dummy log: {file_path}")
    print(f"Parsing {file_path}...")
    
    try:
        df, errors = parser.parse_file(file_path)
        
        print(f"Rows parsed: {len(df)}")
        print(f"Errors: {errors}")
        
        if not df.empty:
            print("Sample data:")
            print(df.head())
            print("Columns:", df.columns)
            
            # Verify Mapping
            # client_ip -> ip
            # verb -> method
            if 'ip' in df.columns and 'method' in df.columns:
                 print("[PASS] Column mapping successful")
            else:
                 print("[FAIL] Column mapping failed")
    except Exception as e:
        print(f"[FAIL] Parsing raised exception: {e}")
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

if __name__ == "__main__":
    verify_json_support()
