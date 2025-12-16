import os
from datetime import datetime

class Reporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_report(self, case_id, coc_text, file_hash, analysis_results):
        """
        Generates a summary report.
        analysis_results: dict containing DataFrames or texts for various checks.
        """
        filename = f"Report_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        file_path = os.path.join(self.output_dir, filename)

        with open(file_path, "w", encoding='utf-8') as f:
            f.write(f"DIGITAL FORENSICS REPORT - LOG ANALYSIS\n")
            f.write(f"=======================================\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Case ID: {case_id}\n")
            f.write(f"Evidence File Hash (SHA256): {file_hash}\n\n")

            # Executive Summary
            f.write(f"EXECUTIVE SUMMARY\n")
            f.write(f"-----------------\n")
            threats_found = []
            
            # Check for high severity threats
            if analysis_results.get('brute_force') is not None and not analysis_results.get('brute_force').empty:
                threats_found.append("CRITICAL: Potential Brute Force Attack Patterns Detected")
            
            if analysis_results.get('high_volume') is not None and not analysis_results.get('high_volume').empty:
                threats_found.append("HIGH: High Volume Traffic (Possible Denial of Service / Scanner)")
                
            if analysis_results.get('exfiltration') is not None and not analysis_results.get('exfiltration').empty:
                threats_found.append("HIGH: Potential Data Exfiltration (Large Response Sizes)")

            if analysis_results.get('suspicious') is not None and not analysis_results.get('suspicious').empty:
                threats_found.append("MEDIUM: Suspicious User Agents Detected")
            
            if analysis_results.get('forbidden') is not None and not analysis_results.get('forbidden').empty:
                threats_found.append("MEDIUM: Access Attempts to Forbidden/Sensitive Files")

            if threats_found:
                for threat in threats_found:
                    f.write(f" [!] {threat}\n")
            else:
                f.write(f" [i] No significant threats detected. Traffic appears normal.\n")
            f.write(f"\n")

            f.write(f"CHAIN OF CUSTODY\n")
            f.write(f"----------------\n")
            f.write(coc_text)
            f.write(f"\n\n")

            f.write(f"ANALYSIS RESULTS\n")
            f.write(f"================\n")
            
            # Traffic Stats
            stats = analysis_results.get('stats')
            if stats:
                f.write(f" [i] Traffic Summary:\n")
                f.write(f"     Total Requests: {stats.get('Total Requests', 0)}\n")
                f.write(f"     Successful/Benign: {stats.get('Successful (Normal)', 0)}\n")
                f.write(f"     Failed/Errors: {stats.get('Failed/Error', 0)}\n\n")

            # High Volume IPs
            f.write(f" [!] High Volume IPs (Potential DoS/Scanners):\n")
            high_vol = analysis_results.get('high_volume')
            if high_vol is not None and not high_vol.empty:
                f.write(high_vol.to_string(index=False))
            else:
                f.write("No high volume IPs detected.")
            f.write(f"\n\n")

            # Forbidden Files
            f.write(f" [!] Access to Sensitive/Forbidden Files:\n")
            forbidden = analysis_results.get('forbidden')
            if forbidden is not None and not forbidden.empty:
                f.write(forbidden.to_string(index=False))
            else:
                f.write("No sensitive file access detected.")
            f.write(f"\n\n")

            # Suspicious User Agents
            f.write(f" [!] Suspicious User Agents:\n")
            suspicious = analysis_results.get('suspicious')
            if suspicious is not None and not suspicious.empty:
                f.write(suspicious.to_string(index=False))
            else:
                f.write("No suspicious user agents detected.")
            f.write(f"\n\n")
            
            # Error Stats
            f.write(f" [!] HTTP Error Codes (4xx/5xx):\n")
            errors = analysis_results.get('errors')
            if errors is not None and not errors.empty:
                f.write(errors.to_string(index=False))
            else:
                f.write("No significant errors found.")
            f.write(f"\n\n")

            # Data Exfiltration
            f.write(f" [!] Potential Data Exfiltration (Large Responses):\n")
            exfil = analysis_results.get('exfiltration')
            if exfil is not None and not exfil.empty:
                f.write(exfil.to_string(index=False))
            else:
                f.write("No unusually large responses detected.")
            f.write(f"\n\n")

            # Brute Force
            f.write(f" [!] Potential Brute Force (High Auth Failures):\n")
            brute = analysis_results.get('brute_force')
            if brute is not None and not brute.empty:
                f.write(brute.to_string(index=False))
            else:
                f.write("No significant brute force attempts detected.")
            f.write(f"\n\n")

            # IDS Alerts
            f.write(f" [!] Intrusion Detection System (IDS) Alerts:\n")
            ids_alerts = analysis_results.get('ids_alerts')
            if ids_alerts is not None and not ids_alerts.empty:
                f.write(ids_alerts.to_string(index=False))
            else:
                f.write("No IDS alerts detected.")
            f.write(f"\n\n")

            f.write(f"END OF REPORT\n")

        return file_path
