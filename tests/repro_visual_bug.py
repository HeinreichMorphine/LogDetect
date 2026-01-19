
import sys
import os
import pandas as pd
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from modules.reporter import Reporter

def verify_fix():
    print("Verifying visual bug fix...")
    reporter = Reporter(output_dir="tests/output")
    
    # Create dummy analysis results with long text
    long_text = "This is a very long path that should wrap around in the table cell instead of running off the page or overlapping with other text. " * 5
    
    data = {
        'timestamp': ['2026-01-16 12:00:00', '2026-01-16 12:01:00'],
        'ip': ['192.168.1.1', '10.0.0.1'],
        'method': ['GET', 'POST'],
        'path': [long_text, '/short/path'],
        'status': [200, 404],
        'size': [1234, 5678]
    }
    df = pd.DataFrame(data)
    
    analysis_results = {
        'exfiltration': df,
        'stats': {'Total Requests': 2, 'Successful (Normal)': 1, 'Failed/Error': 1}
    }
    
    coc_text = "Step 1: Acquired evidence.\nStep 2: Analyzed logs.\nStep 3: Generated report."
    
    output_path = reporter.generate_pdf_report(
        case_id="TEST-CASE-001",
        coc_text=coc_text,
        file_hash="dummy_hash_123",
        analysis_results=analysis_results,
        integrity_verified=True,
        file_path_evidence="C:/fake/path/to/evidence.log",
        file_size=1024
    )
    
    if output_path and os.path.exists(output_path):
        print(f"SUCCESS: Report generated at {output_path}")
    else:
        print("FAILURE: Report generation failed.")

if __name__ == "__main__":
    verify_fix()
