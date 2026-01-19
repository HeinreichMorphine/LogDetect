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
        Generates a professional PDF forensic report with 6 specific sections.
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
        
        # --- 1. Header & Metadata ---
        elements.append(Paragraph("DIGITAL FORENSIC ANALYSIS REPORT", title_style))
        elements.append(Paragraph("1. Header & Metadata", header_style))
        elements.append(Paragraph(f"<b>Tool:</b> NetForensics Analyzer v1.0", normal_style))
        elements.append(Paragraph(f"<b>Date (UTC):</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", normal_style))
        elements.append(Paragraph(f"<b>Case Ref ID:</b> {case_id}", normal_style))
        elements.append(Paragraph(f"<b>Examiner:</b> {examiner_name}", normal_style))
        elements.append(Paragraph(f"<b>System Hostname:</b> {socket.gethostname()}", normal_style))
        elements.append(Spacer(1, 20))

        # --- 2. Evidence Acquisition ---
        elements.append(Paragraph("2. Evidence Acquisition", header_style))
        elements.append(Paragraph("The following evidence was acquired for analysis:", normal_style))
        evidence_data = [
            ["Attribute", "Value"],
            ["Evidence File", os.path.basename(file_path_evidence)],
            ["File Path", file_path_evidence],
            ["File Size", f"{file_size} bytes ({file_size/1024:.2f} KB)"],
            ["Ingress Hash (SHA-256)", file_hash],
            ["Acquisition Status", "SUCCESS"]
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

        # --- 3. Executive Summary ---
        elements.append(Paragraph("3. Executive Summary", header_style))
        elements.append(Paragraph(f"<b>Scan Duration:</b> {scan_duration}", normal_style))
        
        stats = analysis_results.get('stats', {})
        total_reqs = stats.get('Total Requests', 'N/A')
        elements.append(Paragraph(f"<b>Total Artifacts Analyzed:</b> {total_reqs} requests", normal_style))
        
        elements.append(Paragraph("<b>Key Findings:</b>", normal_style))
        threats = self._get_threat_summary(analysis_results)
        if threats:
            for threat in threats:
                elements.append(Paragraph(f"• {threat}", normal_style))
        else:
            elements.append(Paragraph("• No significant malicious patterns detected.", normal_style))
        elements.append(Spacer(1, 20))

        # --- 4. Detailed Findings ---
        elements.append(Paragraph("4. Detailed Findings", header_style))

        # Define cell style for wrapping text
        cell_style = ParagraphStyle('CellStyle', parent=styles['Normal'], fontSize=8, leading=10)
        
        for section, data in analysis_results.items():
            if section == 'stats': continue
            if hasattr(data, 'empty') and data.empty: continue # Skip empty findings
            if data is None: continue

            section_title = section.replace('_', ' ').title()
            elements.append(Paragraph(f"<b>{section_title}</b>", styles['Heading3']))
            
            # Convert DataFrame to list of lists for Table
            if hasattr(data, 'columns'):
                # Limit rows to 25 to focus on most important (Top Attackers) and prevent clutter
                limit = 25
                limited_data = data.head(limit)
                
                # Prepare Header
                headers = [Paragraph(f"<b>{col}</b>", cell_style) for col in limited_data.columns]
                table_data = [headers]
                
                # Prepare Rows with Paragraphs for wrapping
                for _, row in limited_data.iterrows():
                    row_data = []
                    for cell in row:
                        cell_text = str(cell)
                        # Safety truncate
                        if len(cell_text) > 2000: 
                            cell_text = cell_text[:2000] + "[...TRUNCATED]"
                        row_data.append(Paragraph(cell_text, cell_style))
                    table_data.append(row_data)

                # Determine column widths
                total_width = 480
                col_count = len(limited_data.columns)
                
                if col_count > 0:
                    col_widths = [total_width/col_count] * col_count
                    
                    t = Table(table_data, colWidths=col_widths)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    elements.append(t)
                    
                    if len(data) > limit:
                        elements.append(Paragraph(f"<i>(Showing top {limit} of {len(data)} records. Full data available in raw logs.)</i>", normal_style))
            else:
                # Text data (if any)
                elements.append(Paragraph(str(data), normal_style))
            
            elements.append(Spacer(1, 10))
        
        # --- 5. Audit Trail ---
        elements.append(PageBreak())
        elements.append(Paragraph("5. Audit Trail", header_style))
        elements.append(Paragraph("Chronological record of evidence handling and analysis steps:", normal_style))
        elements.append(Spacer(1, 10))
        
        # Format CoC text
        coc_lines = coc_text.split('\n')
        for line in coc_lines:
            if line.strip():
                elements.append(Paragraph(line, code_style))
        elements.append(Spacer(1, 20))

        # --- 6. Conclusion and Integrity ---
        elements.append(Paragraph("6. Conclusion and Integrity", header_style))
        
        integrity_status = "MATCH" if integrity_verified else "MISMATCH"
        integrity_color = colors.green if integrity_verified else colors.red
        
        elements.append(Paragraph("<b>Final Integrity Verification:</b>", normal_style))
        
        # Hash Comparison Table
        # Use Paragraph for hash to ensure wrapping within the cell
        hash_style = ParagraphStyle('HashStyle', parent=styles['Normal'], fontSize=8, leading=9, splitLongWords=1)
        
        # Helper to format hash for display (optional split, but Paragraph handles it)
        def format_hash(h):
            return Paragraph(h, hash_style)
        
        hash_data = [
            ["Stage", "SHA-256 Hash", "Status"],
            ["Original (Ingress)", format_hash(file_hash), "VERIFIED"],
            ["Processed (Egress)", format_hash(egress_hash), integrity_status]
        ]
        
        # Adjusted widths to give more space to Hash
        t_hash = Table(hash_data, colWidths=[100, 350, 80])
        t_hash.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), # Vertical center
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black), # Thinner grid
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            # Highlight Status Cells
            ('BACKGROUND', (2, 2), (2, 2), integrity_color),
            ('TEXTCOLOR', (2, 2), (2, 2), colors.white),
            ('FONTNAME', (2, 2), (2, 2), 'Helvetica-Bold'),
            ('ALIGN', (2, 1), (2, 2), 'CENTER'), # Center align status
        ]))
        elements.append(t_hash)
        
        elements.append(Spacer(1, 15))
        if integrity_verified:
             elements.append(Paragraph("<b>CONCLUSION:</b> The evidence has been analyzed successfully and its integrity was maintained throughout the process.", normal_style))
        else:
             elements.append(Paragraph("<b>CONCLUSION: WARNING - INTEGRITY CHECK FAILED.</b> The evidence file may have been modified during analysis.", ParagraphStyle('Warn', parent=styles['Normal'], textColor=colors.red)))

        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"<i>Report generated by LogDetect on {datetime.now().strftime('%Y-%m-%d')}</i>", normal_style))

        try:
            doc.build(elements)
            print(f"PDF Report generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"Error generating PDF: {e}")
            return None

    def _get_threat_summary(self, analysis_results):
        threats = []
        
        # Valid Checks
        if analysis_results.get('high_volume') is not None and not analysis_results.get('high_volume').empty:
            threats.append("HIGH: High Volume Traffic (Possible Denial of Service / Scanner)")

        if analysis_results.get('directory_traversal') is not None and not analysis_results.get('directory_traversal').empty:
            threats.append("CRITICAL: Directory Traversal Attempts Detected")
            
        if analysis_results.get('vuln_scanning') is not None and not analysis_results.get('vuln_scanning').empty:
            threats.append("HIGH: Vulnerability Scanning Patterns Detected")

        risk_df = analysis_results.get('risk_score')
        if risk_df is not None and not risk_df.empty:
            high_risk_count = len(risk_df[risk_df['risk_score'] > 50])
            if high_risk_count > 0:
                threats.append(f"CRITICAL: {high_risk_count} IPs with High/Critical Risk Scores")
                
        return threats
