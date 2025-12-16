import sys
import os
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.parser import LogParser

def verify_csv():
    parser = LogParser()
    file_path = "C:/Users/kiddp/Downloads/FORENSIC/cybercrime_forensic_dataset.csv"
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    print(f"Parsing {file_path}...")
    df, errors = parser.parse_file(file_path)
    
    print(f"Rows parsed: {len(df)}")
    print(f"Errors: {errors}")
    
    if not df.empty:
        print("Sample data:")
        print(df.head())
        print("Columns:", df.columns)
        
        # Check normalization
        required = ['ip', 'timestamp', 'method', 'path']
        missing = [col for col in required if col not in df.columns]
        if not missing:
            print("[PASS] Essential columns present.")
        else:
            print(f"[FAIL] Missing columns: {missing}")

if __name__ == "__main__":
    verify_csv()
