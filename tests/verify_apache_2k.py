import sys
import os
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.parser import LogParser

def verify_file():
    parser = LogParser()
    file_path = "C:/Users/kiddp/Downloads/FORENSIC/Apache_2k.log"
    
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

if __name__ == "__main__":
    verify_file()
