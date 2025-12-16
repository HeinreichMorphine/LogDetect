import sys
import os
import pandas as pd

# Add root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.evidence import EvidenceHandler
from modules.parser import LogParser
from modules.analyzer import LogAnalyzer
from modules.reporter import Reporter

def run_verification():
    print("--- Starting Verification ---")
    
    # 1. Evidence Handler
    ev = EvidenceHandler()
    ev.set_case_details("TEST-001", "Automated Tester")
    print("[PASS] EvidenceHandler initialized")

    # 2. Parser
    parser = LogParser()
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'sample_logs', 'access.log'))
    
    if not os.path.exists(log_path):
        print(f"[FAIL] Sample log not found at {log_path}")
        return

    df, errors = parser.parse_file(log_path)
    if df is not None and not df.empty:
        print(f"[PASS] Parsed {len(df)} lines with {errors} errors")
    else:
        print("[FAIL] Parsing failed or empty dataframe")
        return

    # 3. Analyzer
    analyzer = LogAnalyzer(df)
    
    # Check High Volume (Threshold 1 for test)
    high_vol = analyzer.detect_high_volume_ips(threshold=1)
    if not high_vol.empty:
        print(f"[PASS] Detected {len(high_vol)} high volume IPs")
    else:
        print("[WARN] No high volume IPs detected (might be expected)")

    # Check Forbidden
    forbidden = analyzer.detect_forbidden_files()
    if not forbidden.empty:
        print(f"[PASS] Detected {len(forbidden)} forbidden file accesses")
    else:
        print("[FAIL] Failed to detect known forbidden file access in sample")

    # Check Suspicious Agents
    suspicious = analyzer.detect_suspicious_user_agents()
    if not suspicious.empty:
        print(f"[PASS] Detected {len(suspicious)} suspicious user agents")
    else:
        print("[FAIL] Failed to detect known suspicious user agent")

    # 4. Reporter
    reporter = Reporter(output_dir='test_reports')
    results = {
        'high_volume': high_vol,
        'forbidden': forbidden,
        'errors': analyzer.analyze_status_codes(),
        'suspicious': suspicious
    }
    report_path = reporter.generate_report("TEST-001", ev.get_coc_text(), "DUMMY_HASH", results)
    
    if os.path.exists(report_path):
        print(f"[PASS] Report generated at {report_path}")
    else:
        print("[FAIL] Report generation failed")

    print("--- Verification Complete ---")

if __name__ == "__main__":
    run_verification()
