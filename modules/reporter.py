import os
import socket
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image

class Reporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_report(self, case_id, coc_text, file_hash, analysis_results, integrity_verified=None, 
                       examiner_name="Unknown", file_path="Unknown", file_size=0, scan_duration="N/A"):
        """
        Legacy text report generation (kept for backup/compatibility).
        """
        return self.generate_text_report(case_id, coc_text, file_hash, analysis_results, integrity_verified)

    def generate_text_report(self, case_id, coc_text, file_hash, analysis_results, integrity_verified=None):
        filename = f"Report_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        file_path = os.path.join(self.output_dir, filename)

        with open(file_path, "w", encoding='utf-8') as f:
            f.write(f"DIGITAL FORENSICS REPORT - LOG ANALYSIS\n")
            f.write(f"=======================================\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Case ID: {case_id}\n")
            f.write(f"Evidence File Hash (SHA256): {file_hash}\n")
            
            # Integrity Check Section
            f.write(f"\nEVIDENCE INTEGRITY CHECK\n")
            f.write(f"------------------------\n")
            if integrity_verified:
                f.write(f" [PASS] Post-analysis hash matches original hash.\n")
                f.write(f"        Evidence integrity has been preserved throughout the analysis.\n")
            elif integrity_verified is False:
                f.write(f" [FAIL] Post-analysis hash DOES NOT match original hash!\n")
                f.write(f"        WARNING: The evidence file may have been modified.\n")
            else:
                f.write(f" [N/A]  Post-analysis verification was not performed.\n")
            f.write(f"\n")

            # Executive Summary
            f.write(f"EXECUTIVE SUMMARY\n")
            f.write(f"-----------------\n")
            threats_found = self._get_threat_summary(analysis_results)
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

            # Detailed Findings
            for section, data in analysis_results.items():
                if section == 'stats': continue
                f.write(f" [!] {section.replace('_', ' ').title()}:\n")
                if data is not None and not data.empty:
                    f.write(data.to_string(index=False))
                else:
                    f.write("None detected.")
                f.write(f"\n\n")

            f.write(f"END OF REPORT\n")

        return file_path

    def generate_pdf_report(self, case_id, coc_text, file_hash, analysis_results, integrity_verified=None,
                           examiner_name="Unknown", file_path_evidence="Unknown", file_size=0, scan_duration="N/A", egress_hash="Pending"):
        """
        Generates a professional PDF forensic report.
        """
        filename = f"Report_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        output_path = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Custom Styles
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=20, alignment=1)
        header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=14, spaceAfter=10, color=colors.darkblue)
        normal_style = styles['Normal']
        code_style = ParagraphStyle('Code', parent=styles['Code'], fontSize=8, fontName='Courier')
        
        # 1. Header & Case Metadata
        elements.append(Paragraph("DIGITAL FORENSIC ANALYSIS REPORT", title_style))
        elements.append(Paragraph(f"<b>Tool:</b> NetForensics Analyzer v1.0", normal_style))
        elements.append(Paragraph(f"<b>Date (UTC):</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", normal_style))
        elements.append(Paragraph(f"<b>Case Ref ID:</b> {case_id}", normal_style))
        elements.append(Paragraph(f"<b>Examiner:</b> {examiner_name}", normal_style))
        elements.append(Paragraph(f"<b>System Hostname:</b> {socket.gethostname()}", normal_style))
        elements.append(Spacer(1, 20))

        # 2. Evidence Acquisition & Integrity
        elements.append(Paragraph("Evidence Acquisition & Integrity", header_style))
        evidence_data = [
            ["Attribute", "Value"],
            ["Evidence File", os.path.basename(file_path_evidence)],
            ["File Path", file_path_evidence],
            ["File Size", f"{file_size} bytes ({file_size/1024:.2f} KB)"],
            ["Ingress Hash (SHA-256)", file_hash],
            ["Verification Status", "VERIFIED (Pre-Analysis)"]
        ]
        t = Table(evidence_data, colWidths=[150, 350])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))

        # 3. Executive Summary
        elements.append(Paragraph("Executive Summary", header_style))
        elements.append(Paragraph(f"<b>Scan Duration:</b> {scan_duration}", normal_style))
        
        stats = analysis_results.get('stats', {})
        total_reqs = stats.get('Total Requests', 'N/A')
        elements.append(Paragraph(f"<b>Total Artifacts Analyzed:</b> {total_reqs} requests", normal_style))
        
        elements.append(Paragraph("<b>Findings Overview:</b>", normal_style))
        threats = self._get_threat_summary(analysis_results)
        if threats:
            for threat in threats:
                elements.append(Paragraph(f"• {threat}", normal_style))
        else:
            elements.append(Paragraph("• No significant malicious patterns detected.", normal_style))
        elements.append(Spacer(1, 20))

        # 4. Detailed Forensic Findings
        elements.append(Paragraph("Detailed Forensic Findings", header_style))
        
        for section, data in analysis_results.items():
            if section == 'stats': continue
            if hasattr(data, 'empty') and data.empty: continue # Skip empty findings
            if data is None: continue

            section_title = section.replace('_', ' ').title()
            elements.append(Paragraph(f"<b>{section_title}</b>", styles['Heading3']))
            
            # Convert DataFrame to list of lists for Table
            if hasattr(data, 'columns'):
                # Limit rows to 50 to prevent PDF explosion
                limited_data = data.head(50)
                table_data = [limited_data.columns.to_list()] + limited_data.values.tolist()
                
                # Wrap long text in cells or it will break table
                # (Simple text truncation for now specifically for PDF safety)
                safe_table_data = []
                for row in table_data:
                    safe_row = [str(cell)[:50] + "..." if len(str(cell)) > 50 else str(cell) for cell in row]
                    safe_table_data.append(safe_row)

                # Determine column widths dynamically or fixed
                col_count = len(safe_table_data[0])
                if col_count > 0:
                    t = Table(safe_table_data, colWidths=[400/col_count]*col_count)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ]))
                    elements.append(t)
                    if len(data) > 50:
                        elements.append(Paragraph(f"<i>(Showing 50 of {len(data)} records)</i>", normal_style))
            else:
                # Text data (if any)
                elements.append(Paragraph(str(data), normal_style))
            
            elements.append(Spacer(1, 10))
        
        # 5. Chain of Custody (Audit Trail)
        elements.append(PageBreak())
        elements.append(Paragraph("Audit Trail / Chain of Custody", header_style))
        elements.append(Paragraph("The following log demonstrates the timeline of analysis and evidence handling.", normal_style))
        elements.append(Spacer(1, 10))
        
        # Format CoC text
        coc_lines = coc_text.split('\n')
        for line in coc_lines:
            if line.strip():
                elements.append(Paragraph(line, code_style))
        elements.append(Spacer(1, 20))

        # 6. Conclusion & Integrity Verification
        elements.append(Paragraph("Conclusion & Integrity Verification", header_style))
        
        integrity_status = "MATCH" if integrity_verified else "MISMATCH / ERROR"
        integrity_color = colors.green if integrity_verified else colors.red
        
        elements.append(Paragraph(f"<b>Final Egress Hash (SHA-256):</b> {egress_hash}", normal_style))
        
        t_integrity = Table([
            ["Integrity Check Status", integrity_status]
        ], colWidths=[150, 350])
        t_integrity.setStyle(TableStyle([
            ('BACKGROUND', (1, 0), (1, 0), integrity_color),
            ('TEXTCOLOR', (1, 0), (1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ]))
        elements.append(t_integrity)
        
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("<i>Disclaimer: This report was generated automatically. No warranties implied.</i>", normal_style))

        try:
            doc.build(elements)
            print(f"PDF Report generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"Error generating PDF: {e}")
            return None

    def _get_threat_summary(self, analysis_results):
        threats = []
        if analysis_results.get('brute_force') is not None and not analysis_results.get('brute_force').empty:
            threats.append("CRITICAL: Potential Brute Force Attack Patterns Detected")
        
        if analysis_results.get('high_volume') is not None and not analysis_results.get('high_volume').empty:
            threats.append("HIGH: High Volume Traffic (Possible Denial of Service / Scanner)")
            
        if analysis_results.get('exfiltration') is not None and not analysis_results.get('exfiltration').empty:
            threats.append("HIGH: Potential Data Exfiltration (Large Response Sizes)")

        if analysis_results.get('suspicious') is not None and not analysis_results.get('suspicious').empty:
            threats.append("MEDIUM: Suspicious User Agents Detected")
        
        if analysis_results.get('forbidden') is not None and not analysis_results.get('forbidden').empty:
            threats.append("MEDIUM: Access Attempts to Forbidden/Sensitive Files")
            
        # Add IDS Alerts
        if analysis_results.get('ids_alerts') is not None and not analysis_results.get('ids_alerts').empty:
            threats.append(f"MEDIUM: {len(analysis_results.get('ids_alerts'))} IDS Alerts Triggered")
            
        return threats
