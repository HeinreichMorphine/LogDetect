import sys
import os
import pandas as pd
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.reporter import Reporter

def test_pdf_generation():
    print("Testing PDF Generation...")
    
    # Mock Data
    case_id = "TEST-CASE-001"
    coc_text = "2024-01-01 10:00:00 - Evidence Acquired\n2024-01-01 10:05:00 - Hash Calculated"
    file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    # Mock Analysis Results
    analysis_results = {
        'stats': {'Total Requests': 1500, 'Successful (Normal)': 1400, 'Failed/Error': 100},
        'brute_force': pd.DataFrame([{'ip': '192.168.1.100', 'failures': 50}]),
        'high_volume': pd.DataFrame([{'ip': '10.0.0.5', 'count': 5000}]),
        'forbidden': pd.DataFrame([{'ip': '192.168.1.101', 'path': '/etc/passwd'}]),
        'suspicious': pd.DataFrame(), # Empty
        'exfiltration': None, # None
        'risk_score': pd.DataFrame([{'ip': '192.168.1.100', 'risk_score': 95, 'severity': 'CRITICAL'}])
    }
    
    reporter = Reporter(output_dir="test_reports")
    
    # Generate PDF
    pdf_path = reporter.generate_pdf_report(
        case_id=case_id,
        coc_text=coc_text,
        file_hash=file_hash,
        analysis_results=analysis_results,
        integrity_verified=True,
        examiner_name="Test Examiner",
        file_path_evidence="C:\\Evidence\\disk.img",
        file_size=102400,
        scan_duration="00:05:30",
        egress_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    
    if pdf_path and os.path.exists(pdf_path):
        print(f"SUCCESS: PDF Report generated at {pdf_path}")
        print(f"File size: {os.path.getsize(pdf_path)} bytes")
    else:
        print("FAILURE: PDF Report was not generated.")

if __name__ == "__main__":
    test_pdf_generation()
