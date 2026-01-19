import socket
import os
import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
import pandas as pd
import threading
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import matplotlib.pyplot as plt

# Import local modules
from modules.evidence import EvidenceHandler
from modules.parser import LogParser
from modules.analyzer import LogAnalyzer
from modules.reporter import Reporter

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# Theme Colors (Cyberpunk/Dark Modern)
COLORS = {
    "bg_main": "#0f0f1e",       # Deep Blue/Black Background
    "bg_sidebar": "#1a1a2e",    # Slightly Lighter Sidebar
    "bg_card": "#16213e",       # Card Background
    "primary": "#4ecca3",       # Teal/Green Accent (or "#3B8ED0" Blue)
    "secondary": "#6c63ff",     # Purple Accent
    "text": "#e94560",          # Accent Text
    "text_light": "#ffffff",    # Main Text
    "button_fg": "#3B8ED0",     # Vibrant Blue
    "button_hover": "#3072A8"
}

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("LogDetect - Digital Forensics Tool")
        self.geometry("1100x700")
        self.configure(fg_color=COLORS["bg_main"]) # Main window background

        # Core Objects
        self.evidence_handler = EvidenceHandler()
        self.log_parser = LogParser()
        self.log_analyzer = None # Initialized after parsing
        self.reporter = Reporter()
        self.df = None
        self.current_file_path = None
        self.file_hash = None
        self.scan_start_time = None

        # Layout Configuration
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color=COLORS["bg_sidebar"])
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="LogDetect", font=ctk.CTkFont(size=20, weight="bold"), text_color=COLORS["text_light"])
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.sidebar_button_1 = ctk.CTkButton(self.sidebar_frame, text="Load Evidence", command=self.show_load_frame,
                                              corner_radius=15, fg_color=COLORS["button_fg"], hover_color=COLORS["button_hover"])
        self.sidebar_button_1.grid(row=1, column=0, padx=20, pady=10)
        
        self.sidebar_button_2 = ctk.CTkButton(self.sidebar_frame, text="Analysis Dashboard", command=self.show_analysis_frame,
                                              corner_radius=15, fg_color=COLORS["button_fg"], hover_color=COLORS["button_hover"])
        self.sidebar_button_2.grid(row=2, column=0, padx=20, pady=10)
        
        self.sidebar_button_3 = ctk.CTkButton(self.sidebar_frame, text="Generate Report", command=self.show_report_frame,
                                              corner_radius=15, fg_color=COLORS["button_fg"], hover_color=COLORS["button_hover"])
        self.sidebar_button_3.grid(row=3, column=0, padx=20, pady=10)

        # Main Content Frames
        self.load_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.analysis_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.report_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        self.setup_load_frame()
        self.setup_analysis_frame()
        self.setup_report_frame()

        # Show initial frame
        self.show_load_frame()

    def show_load_frame(self):
        self.select_frame(self.load_frame)

    def show_analysis_frame(self):
        self.select_frame(self.analysis_frame)

    def show_report_frame(self):
        self.select_frame(self.report_frame)
        self.update_report_preview()

    def select_frame(self, frame):
        self.load_frame.grid_forget()
        self.analysis_frame.grid_forget()
        self.report_frame.grid_forget()
        frame.grid(row=0, column=1, sticky="nsew")

    # --- Load Evidence Frame ---
    def setup_load_frame(self):
        self.load_frame.grid_columnconfigure(0, weight=1)
        
        lbl_title = ctk.CTkLabel(self.load_frame, text="Evidence Acquisition", font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_light"])
        lbl_title.grid(row=0, column=0, padx=20, pady=20)

        # Case Details
        self.entry_case_id = ctk.CTkEntry(self.load_frame, placeholder_text="Case ID", width=300, fg_color=COLORS["bg_card"], border_color=COLORS["secondary"], text_color=COLORS["text_light"])
        self.entry_case_id.grid(row=1, column=0, padx=20, pady=10)

        self.entry_investigator = ctk.CTkEntry(self.load_frame, placeholder_text="Investigator Name", width=300, fg_color=COLORS["bg_card"], border_color=COLORS["secondary"], text_color=COLORS["text_light"])
        self.entry_investigator.grid(row=2, column=0, padx=20, pady=10)

        btn_set_details = ctk.CTkButton(self.load_frame, text="Set Case Details", command=self.set_case_details,
                                        corner_radius=15, fg_color=COLORS["button_fg"], hover_color=COLORS["button_hover"])
        btn_set_details.grid(row=3, column=0, padx=20, pady=10)

        # File Loading
        self.btn_load_file = ctk.CTkButton(self.load_frame, text="Select Log File", command=self.browse_file,
                                           corner_radius=15, fg_color=COLORS["secondary"], hover_color=COLORS["primary"], width=200, height=40)
        self.btn_load_file.grid(row=4, column=0, padx=20, pady=(40, 10))

        self.lbl_file_info = ctk.CTkLabel(self.load_frame, text="No file loaded.", text_color=COLORS["text_light"])
        self.lbl_file_info.grid(row=5, column=0, padx=20, pady=10)

        # Hash Display
        self.lbl_hash = ctk.CTkLabel(self.load_frame, text="Hash: N/A", text_color="gray")
        self.lbl_hash.grid(row=6, column=0, padx=20, pady=(10, 0))

        # Threat Summary
        self.lbl_threat_summary = ctk.CTkLabel(self.load_frame, text="Threat Summary: Waiting for file...", text_color="gray", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_threat_summary.grid(row=7, column=0, padx=20, pady=(5, 5))

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self.load_frame, width=400, height=15, corner_radius=10, progress_color=COLORS["secondary"])
        self.progress_bar.grid(row=8, column=0, padx=20, pady=(0, 20))
        self.progress_bar.set(0) # Start at 0

        # CoC Log Preview
        lbl_coc = ctk.CTkLabel(self.load_frame, text="Chain of Custody Log:", anchor="w", text_color=COLORS["text_light"])
        lbl_coc.grid(row=9, column=0, padx=20, pady=(20, 5), sticky="w")
        
        self.txt_coc = ctk.CTkTextbox(self.load_frame, height=180)
        self.txt_coc.grid(row=9, column=0, padx=20, pady=10, sticky="ew")

    def set_case_details(self):
        case_id = self.entry_case_id.get()
        investigator = self.entry_investigator.get()
        if case_id and investigator:
            self.evidence_handler.set_case_details(case_id, investigator)
            self.evidence_handler.log_action("Case Initialized", f"ID: {case_id}, Investigator: {investigator}")
            self.refresh_coc()
            messagebox.showinfo("Success", "Case details updated.")
        else:
            messagebox.showwarning("Input Error", "Please enter both Case ID and Investigator Name.")

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Log Files", "*.log *.txt *.csv *.json *.jsonl"), ("All Files", "*.*")])
        if file_path:
            self.current_file_path = file_path
            self.lbl_file_info.configure(text=f"Selected: {file_path}")
            self.lbl_threat_summary.configure(text="Scanning...", text_color="orange")
            
            # Threading for I/O
            t = threading.Thread(target=self.process_file_load)
            t.start()

    def process_file_load(self):
        try:
            # 1. Calculate Hash & Preserve Evidence (Imp 2)
            self.scan_start_time = datetime.datetime.now()
            self.evidence_handler.log_action("Evidence Acquired", f"File: {self.current_file_path}")
            self.file_hash = self.evidence_handler.calculate_hash(self.current_file_path)
            self.lbl_hash.configure(text=f"SHA256: {self.file_hash}")
            
            try:
                preserved_path = self.evidence_handler.preserve_evidence(self.current_file_path)
                # Visual verification (Imp 4)
                self.lbl_hash.configure(text=f"SHA256: {self.file_hash} [VERIFIED ✓]", text_color="green")
                messagebox.showinfo("Evidence Preserved", f"File securely copied to:\n{preserved_path}")
            except Exception as e:
                self.lbl_hash.configure(text=f"SHA256: {self.file_hash} [FAILED ✗]", text_color="red")
                messagebox.showwarning("Preservation Failed", f"Could not copy evidence: {e}")

            # 2. Parse File
            self.df, errors = self.log_parser.parse_file(self.current_file_path)
            
            if self.df is None:
                raise ValueError("Failed to parse log file. Format might be unsupported or file is empty.")
             
            # Log Context (Imp 5)
            # Simple heuristic since LogParser handles it
            self.lbl_file_info.configure(text=f"Loaded: {self.current_file_path}\n(Log Type Detected)", text_color="green")

            self.evidence_handler.log_action("Log Parsed", f"Rows: {len(self.df)}, Errors: {errors}")

            # 3. Setup Analyzer
            self.log_analyzer = LogAnalyzer(self.df)
            
            # 4. Auto-Scan for Threats
            threats = []
            
            # Check Risk Score (Imp 1)
            risk_scores = self.log_analyzer.calculate_risk_score()
            critical_ips = risk_scores[risk_scores['severity'] == 'CRITICAL']
            if not critical_ips.empty:
                threats.append(f"CRITICAL RISK IPs ({len(critical_ips)})")

            # Check High Volume
            hv = self.log_analyzer.detect_high_volume_ips()
            if not hv.empty:
                threats.append(f"High Volume IPs ({len(hv)})")
                
            # Check Traversal
            if hasattr(self.log_analyzer, 'detect_directory_traversal'):
                 dt = self.log_analyzer.detect_directory_traversal()
                 if not dt.empty:
                     threats.append(f"Directory Traversal ({len(dt)})")

            # Check Vuln Scan
            if hasattr(self.log_analyzer, 'detect_vuln_scanning'):
                 vs = self.log_analyzer.detect_vuln_scanning()
                 if not vs.empty:
                     threats.append(f"Vuln Scanning ({len(vs)})")

            # Update UI
            if threats:
                summary_text = "THREATS DETECTED: " + ", ".join(threats)
                self.lbl_threat_summary.configure(text=summary_text, text_color="red")
            else:
                self.lbl_threat_summary.configure(text="No Threats Detected (Clean)", text_color="green")
            
            self.refresh_coc()
            
            # Optimization
            self.prefetch_geolocation()
            
            self.update_report_preview()
            messagebox.showinfo("Success", "File loaded, preserved, and analyzed successfully!")
            
        except Exception as e:
            self.lbl_threat_summary.configure(text="Error during scan", text_color="red")
            messagebox.showerror("Error", str(e))

    # Speed Optimization: Pre-fetch Geo for top threats so Dashboard is instant
    def prefetch_geolocation(self):
        """Background fetch of GeoIP for top threats with Progress Feedback."""
        try:
            self.lbl_threat_summary.configure(text="Fetching Geolocation Data (Background)...", text_color="orange")
            self.update_idletasks()
            
            targets = set()
            
            # 1. High Volume Candidates (Top 50)
            hv = self.log_analyzer.detect_high_volume_ips()
            if not hv.empty:
                targets.update(hv['ip'].head(50))
                
            # 2. Risk Score Candidates (Top 50)
            risks = self.log_analyzer.calculate_risk_score()
            if not risks.empty:
                targets.update(risks['ip'].head(50))
            
            # 3. Directory Traversal (Top 50)
            if hasattr(self.log_analyzer, 'detect_directory_traversal'):
                dt = self.log_analyzer.detect_directory_traversal()
                if not dt.empty:
                    targets.update(dt['ip'].value_counts().head(50).index)

            # 4. Vuln Scanning (Top 50)
            if hasattr(self.log_analyzer, 'detect_vuln_scanning'):
                 vs = self.log_analyzer.detect_vuln_scanning()
                 if not vs.empty:
                     targets.update(vs['ip'].value_counts().head(50).index)
            
            # Fetch with Progress
            total = len(targets)
            done = 0
            
            # Reset Bar
            self.progress_bar.set(0)
            
            for ip in list(targets):
                self.log_analyzer.get_geolocation(ip)
                done += 1
                
                # Update Bar & Text
                progress = done / total if total > 0 else 1
                if done % 2 == 0 or done == total: # Update frequently enough for smooth visual
                    self.lbl_threat_summary.configure(text=f"Fetching Geolocation... ({done}/{total})", text_color="orange")
                    self.progress_bar.set(progress)
                    self.update_idletasks()
            
            self.lbl_threat_summary.configure(text="Scan Complete. Geo Data Ready.", text_color="green")
            self.progress_bar.set(1) # Ensure full bar
            
            # Save Cache to Disk
            self.log_analyzer.save_cache()
                
        except Exception as e:
            print(f"Prefetch error: {e}")

    def refresh_coc(self):
        self.txt_coc.delete("0.0", "end")
        self.txt_coc.insert("0.0", self.evidence_handler.get_coc_text())

    # --- Analysis Frame ---
    def setup_analysis_frame(self):
        self.analysis_frame.grid_columnconfigure(0, weight=1)
        self.analysis_frame.grid_rowconfigure(4, weight=1) # Chart area

        lbl_title = ctk.CTkLabel(self.analysis_frame, text="Analysis Dashboard", font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_light"])
        lbl_title.grid(row=0, column=0, padx=20, pady=20)

        # Controls
        controls_frame = ctk.CTkFrame(self.analysis_frame, fg_color="transparent")
        controls_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        controls_frame.grid_columnconfigure((0,1,2,3), weight=1)

        # Style dict for analysis buttons
        btn_style = {"corner_radius": 15, "fg_color": COLORS["bg_card"], "hover_color": COLORS["secondary"], "border_color": COLORS["primary"], "border_width": 1, "height": 50, "font": ctk.CTkFont(size=13)}

        # Row 0: Critical Analysis (Apache Focused)
        btn_risk = ctk.CTkButton(controls_frame, text="Risk Scoring", command=self.check_risk_score, 
                                 corner_radius=15, fg_color="#E03131", hover_color="#C92A2A", border_color="white", border_width=1, height=50, font=ctk.CTkFont(size=13, weight="bold"))
        btn_risk.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        btn_dt = ctk.CTkButton(controls_frame, text="Dir Traversal", command=self.check_directory_traversal, **btn_style)
        btn_dt.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        btn_vs = ctk.CTkButton(controls_frame, text="Vuln Scans", command=self.check_vuln_scans, **btn_style)
        btn_vs.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        
        btn_high_vol = ctk.CTkButton(controls_frame, text="High Volume IPs", command=self.check_high_volume, **btn_style)
        btn_high_vol.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        # Removed Secondary/Tertiary Rows as per user request to "remove other functions"

        # Text Results (and Treeview container)
        self.results_frame = ctk.CTkFrame(self.analysis_frame, fg_color=COLORS["bg_card"], height=150)
        self.results_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew") # Fix: Moved to row 2 to avoid overlapping controls
        self.results_frame.grid_columnconfigure(0, weight=1)
        self.results_frame.grid_rowconfigure(0, weight=1)

        # 1. Textbox (for simple messages)
        self.txt_results = ctk.CTkTextbox(self.results_frame, fg_color=COLORS["bg_card"], text_color=COLORS["text_light"])
        self.txt_results.grid(row=0, column=0, sticky="nsew")
        
        # 2. Treeview (for Structured Data)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", 
                        background="#16213e", # Card bg
                        foreground="white", 
                        fieldbackground="#16213e",
                        rowheight=25)
        style.configure("Treeview.Heading", background="#4ecca3", foreground="black", font=('Arial', 10, 'bold'))
        style.map("Treeview", background=[("selected", "#6c63ff")])

        self.tree = ttk.Treeview(self.results_frame, show="headings")
        self.tree.grid(row=0, column=0, sticky="nsew")
        
        # Scrollbar shared
        vsb = ttk.Scrollbar(self.results_frame, orient="vertical", command=self.tree.yview) # Default to tree
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)
        self.txt_results.configure(yscrollcommand=vsb.set)

        # Tags for highlighting (Imp 3)
        self.tree.tag_configure('row_critical', background='#E03131', foreground='white') # Red
        self.tree.tag_configure('row_high', background='#F08C00', foreground='black')     # Orange

        # Initially hide tree, show text
        self.tree.grid_remove()

        # Chart Frame
        self.chart_frame = ctk.CTkFrame(self.analysis_frame, fg_color=COLORS["bg_card"], corner_radius=15)
        self.chart_frame.grid(row=3, column=0, padx=20, pady=10, sticky="nsew") # Fix: Moved to row 3

    # Helper to Assign ISP and Country (Focus on Geolocation)
    def enrich_with_geo(self, df, ip_col='ip'):
        if df.empty or ip_col not in df.columns:
            return df
        
        # Add columns if missing
        if 'country' not in df.columns: df['country'] = "Pending"
        if 'isp' not in df.columns: df['isp'] = "Pending"
        
        # Fetch Geo for Top 10 items in display list to be responsive
        # (Assuming df passed here is what we want to see)
        for index, row in df.head(10).iterrows():
             try:
                 ip = row[ip_col]
                 # Check cache or fetch
                 c, i = self.log_analyzer.get_geolocation(ip)
                 df.at[index, 'country'] = c
                 df.at[index, 'isp'] = i
             except: pass
        
        # Fill rest with Unknown or Pending
        return df

    def check_high_volume(self):
        if self.log_analyzer:
            res = self.log_analyzer.detect_high_volume_ips()
            if not res.empty:
                res.columns = ['ip', 'count'] # Standardize
                res = self.enrich_with_geo(res, 'ip')
                res.columns = ['IP Address', 'Total Requests (Volume)', 'Country', 'ISP']
            self.display_result("High Volume IPs", res)
            
            # Graph
            if not res.empty:
                self.plot_bar(res.head(10), 'IP Address', 'Total Requests (Volume)', 'Top High Volume IPs')
        else:
            self.display_result("Error", "No data loaded.")

    def check_directory_traversal(self):
        if self.log_analyzer:
            if hasattr(self.log_analyzer, 'detect_directory_traversal'):
                res = self.log_analyzer.detect_directory_traversal()
                # Aggregate for UI cleanliness (like we did for report)
                if not res.empty:
                     summary = res['ip'].value_counts().reset_index()
                     summary.columns = ['ip', 'count']
                     summary = self.enrich_with_geo(summary, 'ip')
                else:
                     summary = res
                
                self.display_result("Directory Traversal Attempts", summary)
                 # Graph
                if not summary.empty:
                    self.plot_bar(summary.head(10), 'ip', 'count', 'Top Traversal Sources')
            else:
                 self.display_result("Feature Missing", "Module update required.")
        else:
            self.display_result("Error", "No data loaded.")

    def check_vuln_scans(self):
        if self.log_analyzer:
            if hasattr(self.log_analyzer, 'detect_vuln_scanning'):
                res = self.log_analyzer.detect_vuln_scanning()
                if not res.empty:
                     summary = res['ip'].value_counts().reset_index()
                     summary.columns = ['ip', 'count']
                     summary = self.enrich_with_geo(summary, 'ip')
                else:
                     summary = res

                self.display_result("Vulnerability Scanning (Known Files)", summary)
                # Graph
                if not summary.empty:
                    self.plot_bar(summary.head(10), 'ip', 'count', 'Top Targeted Paths')
            else:
                 self.display_result("Feature Missing", "Module update required.")
        else:
            self.display_result("Error", "No data loaded.")

    def check_risk_score(self):
        # New Feature: Risk Scoring (Imp 1)
        if self.log_analyzer:
            res = self.log_analyzer.calculate_risk_score()
            
            # Clarify Columns for Display
            if not res.empty:
                res = res.rename(columns={
                    'risk_score': 'Threat Score',
                    'request_count': 'Traffic Volume',
                    'ioc_match': 'Known Bad IP?',
                    'severity': 'Severity Label'
                })
                
            self.display_result("Risk Scoring (Data Intelligence)", res)
            if not res.empty:
                 self.plot_bar(res.head(10), 'ip', 'risk_score', 'Top High Risk IPs')
        else:
             self.display_result("Error", "No data loaded.")

    def check_timeline(self):
         # New Feature: Timeline (Imp 5)
         if self.df is not None:
             if 'timestamp' in self.df.columns:
                 # Ensure datetime
                 try:
                    # Create a copy to not affect global state if redundant
                    temp_df = self.df.copy()
                    if not pd.api.types.is_datetime64_any_dtype(temp_df['timestamp']):
                         temp_df['timestamp'] = pd.to_datetime(temp_df['timestamp'], errors='coerce')
                    
                    # Remove NaT (failed parses)
                    temp_df = temp_df.dropna(subset=['timestamp'])

                    if temp_df.empty:
                        self.display_result("Error", "No valid timestamps found for timeline.")
                        return
                    # Group by hour
                    timeline = temp_df.set_index('timestamp').resample('h').size().reset_index(name='count')
                    self.display_result("Event Timeline (Hourly)", timeline)
                    self.plot_line(timeline, 'timestamp', 'count', 'Event Volume Over Time')
                 except Exception as e:
                     self.display_result("Error", f"Could not generate timeline: {e}")
             else:
                 self.display_result("Error", "Timestamp data missing.")
         else:
             self.display_result("Error", "No data loaded.")

    def export_data_csv(self):
         # New Feature: Structured Data Export (Imp 3)
         if self.df is not None:
             path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
             if path:
                 self.df.to_csv(path, index=False)
                 messagebox.showinfo("Export Successful", f"Data exported to {path}")
         else:
             messagebox.showwarning("Error", "No data to export.")

    def display_result(self, title, data):
        # Update title if possible (add label for this later if needed) or just log it
        
        if isinstance(data, pd.DataFrame):
            # Show Treeview, Hide Textbox
            self.txt_results.grid_remove()
            self.tree.grid()
            
            # Clear existing
            self.tree.delete(*self.tree.get_children())
            
            if data.empty:
                 self.txt_results.grid()
                 self.tree.grid_remove()
                 self.txt_results.delete("0.0", "end")
                 self.txt_results.insert("0.0", f"--- {title} ---\nNo data found.")
                 return

            # Set Columns
            cols = list(data.columns)
            self.tree["columns"] = cols
            for col in cols:
                self.tree.heading(col, text=col)
                self.tree.column(col, width=100, anchor="w") # Adjust width
            
            # Insert Rows with Highlighting
            for index, row in data.iterrows():
                tags = ()
                if 'severity' in row and row['severity'] == 'CRITICAL':
                    tags = ('row_critical',)
                elif 'risk_score' in row and row['risk_score'] > 80:
                    tags = ('row_critical',)
                elif 'status' in row and row['status'] >= 500:
                    tags = ('row_high',)
                
                # Convert all to string
                values = [str(x) for x in row]
                self.tree.insert("", "end", values=values, tags=tags)
                
        else:
            # Show Textbox, Hide Treeview
            self.tree.grid_remove()
            self.txt_results.grid()
            
            self.txt_results.delete("0.0", "end")
            self.txt_results.insert("0.0", f"--- {title} ---\n")
            self.txt_results.insert("end", str(data))
            self.txt_results.see("0.0")

    def plot_line(self, df, x_col, y_col, title):
        # New generic line plotter for Timeline
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        with plt.style.context('dark_background'):
            fig, ax = plt.subplots(figsize=(6, 4))
            fig.patch.set_facecolor(COLORS["bg_card"])
            ax.set_facecolor(COLORS["bg_card"])

            ax.plot(df[x_col], df[y_col], marker='o', linestyle='-', color=COLORS["primary"])
            ax.set_title(title, color="white")
            ax.set_xlabel("Time", color="white")
            ax.set_ylabel("Count", color="white")
            ax.tick_params(colors='white')
            plt.xticks(rotation=45)
            plt.tight_layout()

            canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(side="top", fill="both", expand=True)
            toolbar = NavigationToolbar2Tk(canvas, self.chart_frame)
            toolbar.update()
            canvas.get_tk_widget().pack(side="top", fill="both", expand=True)

    def plot_bar(self, df, x_col, y_col, title):
        # Clear chart frame
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        # Use Dark Background style
        with plt.style.context('dark_background'):
            fig, ax = plt.subplots(figsize=(6, 4))
            fig.patch.set_facecolor(COLORS["bg_card"]) # Match card background
            ax.set_facecolor(COLORS["bg_card"])

            # Ensure data types are handled for plotting
            x_data = df[x_col].astype(str)
            y_data = df[y_col]
            
            # Simple color coding based on risk if applicable
            colors = COLORS["primary"]
            if 'severity' in df.columns:
                 # Map severity to colors
                 color_map = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 'LOW': 'blue', 'NORMAL': 'green'}
                 colors = df['severity'].map(color_map).fillna(COLORS["primary"])

            ax.bar(x_data, y_data, color=colors)
            ax.set_title(title, color="white")
            ax.set_xlabel(x_col, color="white")
            ax.set_ylabel(y_col, color="white")
            ax.tick_params(colors='white')
            
            # Rotate labels if they are long
            if len(x_data) > 0 and len(x_data.iloc[0]) > 10:
                 plt.xticks(rotation=45, ha='right')
            else:
                 plt.xticks(rotation=0)
            plt.tight_layout()

            canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(side="top", fill="both", expand=True)
            
            # Add Toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.chart_frame)
            toolbar.update()
            canvas.get_tk_widget().pack(side="top", fill="both", expand=True)

    # --- Report Frame ---
    def setup_report_frame(self):
        self.report_frame.grid_columnconfigure(0, weight=1)
        
        lbl_title = ctk.CTkLabel(self.report_frame, text="Generate Report", font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_light"])
        lbl_title.grid(row=0, column=0, padx=20, pady=20)

        # Export Buttons
        btn_export_pdf = ctk.CTkButton(self.report_frame, text="Export PDF Report", command=self.export_pdf,
                                   corner_radius=15, fg_color=COLORS["button_fg"], hover_color=COLORS["button_hover"], width=200, height=40)
        btn_export_pdf.grid(row=1, column=0, padx=20, pady=(10, 5)) # Adjusted row and pady

        btn_export_text = ctk.CTkButton(self.report_frame, text="Export Text Report", command=self.export_text,
                                   corner_radius=15, fg_color=COLORS["secondary"], hover_color=COLORS["primary"], width=200, height=40)
        btn_export_text.grid(row=2, column=0, padx=20, pady=(5, 10)) # Adjusted row and pady
        
        lbl_preview = ctk.CTkLabel(self.report_frame, text="Preview:", anchor="w", text_color=COLORS["text_light"])
        lbl_preview.grid(row=3, column=0, padx=20, pady=(10,5), sticky="w") # Adjusted row
        
        self.txt_report_preview = ctk.CTkTextbox(self.report_frame, height=400, fg_color=COLORS["bg_card"], text_color=COLORS["text_light"])
        self.txt_report_preview.grid(row=4, column=0, padx=20, pady=10, sticky="nsew")



    def update_report_preview(self):
        # Generate a preview string
        if self.log_analyzer:
            coc = self.evidence_handler.get_coc_text()
            stats = self.log_analyzer.get_traffic_summary()
            risk = self.log_analyzer.calculate_risk_score()
            
            # Supported Stats
            high_vol = self.log_analyzer.detect_high_volume_ips()
            
            # New Checks
            traversal = pd.DataFrame()
            if hasattr(self.log_analyzer, 'detect_directory_traversal'):
                 traversal = self.log_analyzer.detect_directory_traversal()
            
            vuln = pd.DataFrame()
            if hasattr(self.log_analyzer, 'detect_vuln_scanning'):
                 vuln = self.log_analyzer.detect_vuln_scanning()

            # Build String
            preview = f"Log File: {os.path.basename(self.current_file_path)}\n"
            preview += f"Total Requests: {stats.get('Total Requests', 0)}\n"
            preview += f"Error Rate: {stats.get('Failed/Error', 0)} errors\n\n"
            
            preview += "[THREAT SUMMARY]\n"
            preview += f"High Volume IPs: {len(high_vol)}\n"
            preview += f"Directory Traversal: {len(traversal)}\n"
            preview += f"Vuln Scanning: {len(vuln)}\n"

            high_risk = len(risk[risk['risk_score'] > 50]) if not risk.empty else 0
            preview += f"CRITICAL/HIGH Risk IPs: {high_risk}\n"

            preview += "\n[CHAIN OF CUSTODY (Last 5 Actions)]\n"
            coc_lines = coc.strip().split('\n')
            # Filter distinct actions or just show last few valid lines
            valid_coc = [line for line in coc_lines if line.strip() and not line.startswith('=')]
            for line in valid_coc[-5:]:
                preview += f"{line}\n"
            
            preview += "\n[FULL ANALYSIS]\n"
            preview += "(See exported report for comprehensive details.)"

            self.txt_report_preview.delete("0.0", "end")
            self.txt_report_preview.insert("0.0", preview)
        else:
            self.txt_report_preview.delete("0.0", "end")
            self.txt_report_preview.insert("0.0", "Load and analyze a file first.")

    def _prepare_report_data(self):
        """Helper to gather and split data for PDF (Summary) and Text (Raw) reports."""
        if not self.log_analyzer:
            return None, None, None, None, None

        coc = self.evidence_handler.get_coc_text()
        
        # Integrity Check
        integrity_verified = False
        current_hash = "N/A"
        try:
            current_hash = self.evidence_handler.calculate_hash(self.current_file_path)
            integrity_verified = (current_hash == self.file_hash)
            if integrity_verified:
                self.evidence_handler.log_action("Integrity Check", "Post-analysis hash matches original.")
            else:
                self.evidence_handler.log_action("Integrity Check Failed", f"New Hash: {current_hash}")
        except Exception as e:
            print(f"Integrity check error: {e}")
            integrity_verified = False

        # Get Risk Scores (contains Geolocation for top IPs)
        risk_df = self.log_analyzer.calculate_risk_score()
        
        # Helper to merge Geo info
        def merge_geo(summary_df):
            if summary_df.empty:
                return summary_df
            
            # Initial merge
            if not risk_df.empty and 'country' in risk_df.columns:
                geo_info = risk_df[['ip', 'country', 'isp']]
                merged = summary_df.merge(geo_info, on='ip', how='left')
            else:
                 merged = summary_df.copy()
                 merged['country'] = "Pending"
                 merged['isp'] = "Pending"

            # FILL GAPS
            count = 0
            for index, row in merged.iterrows():
                c = str(row.get('country', 'Pending'))
                if c in ["Pending", "Unknown", "nan", "None"]:
                    try:
                        country, isp = self.log_analyzer.get_geolocation(row['ip'])
                        merged.at[index, 'country'] = country
                        merged.at[index, 'isp'] = isp
                        self.update_idletasks()
                        count += 1
                    except Exception: 
                        pass
            
            merged['country'].fillna('Unknown', inplace=True)
            merged['isp'].fillna('Unknown', inplace=True)
            return merged

        # 1. Directory Traversal
        dt_raw = self.log_analyzer.detect_directory_traversal() if hasattr(self.log_analyzer, 'detect_directory_traversal') else pd.DataFrame()
        if not dt_raw.empty:
            dt_summary = dt_raw['ip'].value_counts().reset_index()
            dt_summary.columns = ['ip', 'traversal_attempts_count']
            sample_paths = dt_raw.groupby('ip')['path'].first().reset_index()
            dt_summary = dt_summary.merge(sample_paths, on='ip', how='left')
            dt_summary.rename(columns={'path': 'sample_payload'}, inplace=True)
            
            dt_pdf = merge_geo(dt_summary.head(10))
            
            dt_text = dt_summary.copy()
            if 'country' in dt_text.columns: dt_text.drop(columns=['country'], inplace=True)
            if 'isp' in dt_text.columns: dt_text.drop(columns=['isp'], inplace=True)
        else:
            dt_pdf = pd.DataFrame()
            dt_text = pd.DataFrame()

        # 2. Vuln Scanning
        vs_raw = self.log_analyzer.detect_vuln_scanning() if hasattr(self.log_analyzer, 'detect_vuln_scanning') else pd.DataFrame()
        if not vs_raw.empty:
             vs_summary = vs_raw['ip'].value_counts().reset_index()
             vs_summary.columns = ['ip', 'scan_attempts_count']
             sample_paths = vs_raw.groupby('ip')['path'].first().reset_index()
             vs_summary = vs_summary.merge(sample_paths, on='ip', how='left')
             vs_summary.rename(columns={'path': 'sample_target'}, inplace=True)
             
             vs_pdf = merge_geo(vs_summary.head(10))
             
             vs_text = vs_summary.copy()
             if 'country' in vs_text.columns: vs_text.drop(columns=['country'], inplace=True)
             if 'isp' in vs_text.columns: vs_text.drop(columns=['isp'], inplace=True)
        else:
             vs_pdf = pd.DataFrame()
             vs_text = pd.DataFrame()
             
        # Risk Score Handling
        risk_pdf = merge_geo(risk_df.head(10))
        
        risk_text = risk_df.copy()
        if 'country' in risk_text.columns: risk_text.drop(columns=['country'], inplace=True, errors='ignore')
        if 'isp' in risk_text.columns: risk_text.drop(columns=['isp'], inplace=True, errors='ignore')

        # High Volume Handling
        hv_pdf = self.log_analyzer.detect_high_volume_ips().head(10)
        hv_text = self.log_analyzer.detect_high_volume_ips()

        results_pdf = {
            'stats': self.log_analyzer.get_traffic_summary(),
            'high_volume': hv_pdf,
            'errors': self.log_analyzer.analyze_status_codes(),
            'risk_score': risk_pdf, 
            'directory_traversal': dt_pdf, 
            'vuln_scanning': vs_pdf,
            'forbidden': pd.DataFrame(), 'suspicious': pd.DataFrame(), 'id_alerts': pd.DataFrame()
        }
        
        results_text = {
            'stats': self.log_analyzer.get_traffic_summary(),
            'high_volume': hv_text,
            'errors': self.log_analyzer.analyze_status_codes(),
            'risk_score': risk_text, 
            'directory_traversal': dt_text, 
            'vuln_scanning': vs_text,
            'forbidden': pd.DataFrame(), 'suspicious': pd.DataFrame(), 'id_alerts': pd.DataFrame()
        }
        
        return results_pdf, results_text, integrity_verified, coc, current_hash

    def export_pdf(self):
        results_pdf, _, integrity_verified, coc, current_hash = self._prepare_report_data()
        if not results_pdf:
            messagebox.showwarning("Error", "No analysis data to report.")
            return

        try:
            file_size = os.path.getsize(self.current_file_path)
            scan_end = datetime.datetime.now()
            duration = "N/A"
            if self.scan_start_time:
                delta = scan_end - self.scan_start_time
                duration = str(delta).split('.')[0] # HH:MM:SS
                
            path = self.reporter.generate_pdf_report(
                case_id=self.evidence_handler.case_id, 
                coc_text=coc, 
                file_hash=self.file_hash, 
                analysis_results=results_pdf, 
                integrity_verified=integrity_verified,
                examiner_name=self.evidence_handler.investigator,
                file_path_evidence=self.current_file_path,
                file_size=file_size,
                scan_duration=duration,
                egress_hash=current_hash if integrity_verified else "HASH_MISMATCH"
            )
            if path:
                messagebox.showinfo("Report Generated", f"PDF Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def export_text(self):
        _, results_text, integrity_verified, coc, _ = self._prepare_report_data()
        if not results_text:
            messagebox.showwarning("Error", "No analysis data to report.")
            return

        try:
            text_path = self.reporter.generate_text_report(self.evidence_handler.case_id, coc, self.file_hash, results_text, integrity_verified)
            if text_path:
                messagebox.showinfo("Report Generated", f"Text Report saved to:\n{text_path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

if __name__ == "__main__":
    app = App()
    app.mainloop()
