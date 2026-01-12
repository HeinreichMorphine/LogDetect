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
        self.lbl_threat_summary.grid(row=7, column=0, padx=20, pady=(5, 10))

        # CoC Log Preview
        lbl_coc = ctk.CTkLabel(self.load_frame, text="Chain of Custody Log:", anchor="w", text_color=COLORS["text_light"])
        lbl_coc.grid(row=8, column=0, padx=20, pady=(20, 5), sticky="w")
        
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
                
            # Check Brute Force
            bf = self.log_analyzer.detect_brute_force()
            if not bf.empty:
                threats.append(f"Brute Force ({len(bf)} IPs)")
                
            # Check Exfiltration
            exfil = self.log_analyzer.detect_large_responses()
            if not exfil.empty:
                threats.append(f"Data Exfiltration ({len(exfil)} events)")
                
            # Check Suspicious UAs
            sus_ua = self.log_analyzer.detect_suspicious_user_agents()
            if not sus_ua.empty:
                threats.append(f"Suspicious UAs ({len(sus_ua)})")
            
            # Check IDS Alerts (New)
            if hasattr(self.log_analyzer, 'detect_ids_alerts'):
                ids_alerts = self.log_analyzer.detect_ids_alerts()
                if not ids_alerts.empty:
                    # Sum counts to get total alerts
                    total_alerts = ids_alerts['count'].sum()
                    threats.append(f"IDS Alerts ({total_alerts})")

            # Update UI
            if threats:
                summary_text = "THREATS DETECTED: " + ", ".join(threats)
                self.lbl_threat_summary.configure(text=summary_text, text_color="red")
            else:
                self.lbl_threat_summary.configure(text="No Threats Detected (Clean)", text_color="green")
            
            self.refresh_coc()
            messagebox.showinfo("Success", "File loaded, preserved, and analyzed successfully!")
            
        except Exception as e:
            self.lbl_threat_summary.configure(text="Error during scan", text_color="red")
            messagebox.showerror("Error", str(e))

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

        btn_high_vol = ctk.CTkButton(controls_frame, text="High Volume IPs", command=self.check_high_volume, **btn_style)
        btn_high_vol.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        btn_forbidden = ctk.CTkButton(controls_frame, text="Forbidden Files", command=self.check_forbidden, **btn_style)
        btn_forbidden.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        btn_errors = ctk.CTkButton(controls_frame, text="Error Analysis", command=self.check_errors, **btn_style)
        btn_errors.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        
        btn_suspicious = ctk.CTkButton(controls_frame, text="Suspicious Agents", command=self.check_suspicious, **btn_style)
        btn_suspicious.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        btn_exfil = ctk.CTkButton(controls_frame, text="Data Exfiltration", command=self.check_exfiltration, **btn_style)
        btn_exfil.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        btn_brute = ctk.CTkButton(controls_frame, text="Brute Force", command=self.check_brute_force, **btn_style)
        btn_brute.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # IDS Alerts (New)
        btn_ids = ctk.CTkButton(controls_frame, text="IDS Alerts", command=self.check_ids_alerts, **btn_style)
        btn_ids.grid(row=1, column=2, padx=5, pady=5, sticky="ew")
        
        # Risk Analysis (New - Imp 1)
        btn_risk = ctk.CTkButton(controls_frame, text="Risk Scoring", command=self.check_risk_score, 
                                 corner_radius=15, fg_color="#E03131", hover_color="#C92A2A", border_color="white", border_width=1, height=50, font=ctk.CTkFont(size=13))
        btn_risk.grid(row=1, column=3, padx=5, pady=5, sticky="ew")

        # Timeline (New - Imp 5)
        btn_timeline = ctk.CTkButton(controls_frame, text="Event Timeline", command=self.check_timeline,
                                     corner_radius=15, fg_color="#1098AD", hover_color="#0B7285", border_color="white", border_width=1, height=50, font=ctk.CTkFont(size=13))
        btn_timeline.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        # Export (New - Imp 3)
        btn_csv = ctk.CTkButton(controls_frame, text="Export CSV Data", command=self.export_data_csv,
                                corner_radius=15, fg_color="#F08C00", hover_color="#E67700", border_color="white", border_width=1, height=50, font=ctk.CTkFont(size=13))
        btn_csv.grid(row=2, column=2, columnspan=2, padx=5, pady=5, sticky="ew")

        # Text Results (and Treeview container)
        self.results_frame = ctk.CTkFrame(self.analysis_frame, fg_color=COLORS["bg_card"], height=150)
        self.results_frame.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")
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
        self.chart_frame.grid(row=4, column=0, padx=20, pady=10, sticky="nsew")

    def check_high_volume(self):
        if self.log_analyzer:
            res = self.log_analyzer.detect_high_volume_ips()
            self.display_result("High Volume IPs", res)
            
            # Graph
            if not res.empty:
                self.plot_bar(res.head(10), 'ip', 'count', 'Top High Volume IPs')
        else:
            self.display_result("Error", "No data loaded.")

    def check_forbidden(self):
        if self.log_analyzer:
            res = self.log_analyzer.detect_forbidden_files()
            self.display_result("Forbidden File Access", res)
            
            # Graph
            if not res.empty:
                chart_data = res['path'].value_counts().reset_index()
                chart_data.columns = ['path', 'count']
                self.plot_bar(chart_data.head(10), 'path', 'count', 'Top Forbidden Paths')
        else:
            self.display_result("Error", "No data loaded.")

    def check_errors(self):
        if self.log_analyzer:
            res = self.log_analyzer.analyze_status_codes()
            self.display_result("Error Code Distribution", res)
            
            # Graph
            if not res.empty:
                self.plot_bar(res, 'status', 'count', 'Error Codes')
        else:
            self.display_result("Error", "No data loaded.")

    def check_suspicious(self):
         if self.log_analyzer:
            res = self.log_analyzer.detect_suspicious_user_agents()
            self.display_result("Suspicious User Agents", res)
            
            # Graph
            if not res.empty:
                chart_data = res['user_agent'].str[:30].value_counts().reset_index()
                chart_data.columns = ['user_agent', 'count']
                self.plot_bar(chart_data.head(10), 'user_agent', 'count', 'Top Suspicious UAs')
         else:
            self.display_result("Error", "No data loaded.")

    def check_exfiltration(self):
         if self.log_analyzer:
            # Default threshold 1MB (1,000,000 bytes)
            res = self.log_analyzer.detect_large_responses(threshold_bytes=1000000)
            self.display_result("Potential Data Exfiltration (>1MB Responses)", res)
            
            # Graph
            if not res.empty:
                 chart_data = res['ip'].value_counts().reset_index()
                 chart_data.columns = ['ip', 'count']
                 self.plot_bar(chart_data.head(10), 'ip', 'count', 'Top IPs (Large Responses)')
         else:
            self.display_result("Error", "No data loaded.")

    def check_brute_force(self):
         if self.log_analyzer:
            res = self.log_analyzer.detect_brute_force()
            self.display_result("Potential Brute Force (High Auth Failures)", res)
            
            # Graph
            if not res.empty:
                self.plot_bar(res.head(10), 'ip', 'count', 'Top Attacking IPs')
         else:
            self.display_result("Error", "No data loaded.")

    def check_ids_alerts(self):
         if self.log_analyzer:
            if hasattr(self.log_analyzer, 'detect_ids_alerts'):
                res = self.log_analyzer.detect_ids_alerts()
                self.display_result("IDS Alerts", res)
                
                # Plot alerts by IP (top 10)
                if not res.empty:
                     # Group by IP for simpler charting if multiple alerts per IP
                     chart_data = res.groupby('ip')['count'].sum().reset_index()
                     self.plot_bar(chart_data.head(10), 'ip', 'count', 'Top Source IPs (IDS Alerts)')
            else:
                 self.display_result("Error", "Analyzer does not support IDS alerts.")
         else:
            self.display_result("Error", "No data loaded.")
            
    def check_risk_score(self):
        # New Feature: Risk Scoring (Imp 1)
        if self.log_analyzer:
            res = self.log_analyzer.calculate_risk_score()
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
                    timeline = temp_df.set_index('timestamp').resample('H').size().reset_index(name='count')
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

        self.btn_export = ctk.CTkButton(self.report_frame, text="Export Text Report", command=self.export_report,
                                        corner_radius=15, fg_color=COLORS["primary"], hover_color=COLORS["secondary"], width=200, height=40)
        self.btn_export.grid(row=1, column=0, padx=20, pady=10)
        
        lbl_preview = ctk.CTkLabel(self.report_frame, text="Preview:", anchor="w", text_color=COLORS["text_light"])
        lbl_preview.grid(row=2, column=0, padx=20, pady=(10,5), sticky="w")
        
        self.txt_report_preview = ctk.CTkTextbox(self.report_frame, height=400, fg_color=COLORS["bg_card"], text_color=COLORS["text_light"])
        self.txt_report_preview.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")



    def update_report_preview(self):
        # Generate a preview string
        if self.log_analyzer:
            coc = self.evidence_handler.get_coc_text()
            stats = self.log_analyzer.get_traffic_summary()
            risk = self.log_analyzer.calculate_risk_score()
            
            # Additional Threat Stats for Preview
            brute_force = self.log_analyzer.detect_brute_force()
            high_vol = self.log_analyzer.detect_high_volume_ips()
            ids_alerts = pd.DataFrame()
            if hasattr(self.log_analyzer, 'detect_ids_alerts'):
                ids_alerts = self.log_analyzer.detect_ids_alerts()
            
            forbidden = self.log_analyzer.detect_forbidden_files()
            suspicious = self.log_analyzer.detect_suspicious_user_agents()
            exfil = self.log_analyzer.detect_large_responses(threshold_bytes=1000000)

            preview = "--- FORENSIC REPORT PREVIEW ---\n\n"
            
            preview += "[EXECUTIVE SUMMARY]\n"
            preview += f"Total Requests: {stats.get('Total Requests', 0)}\n"
            preview += f"Malicious/Suspicious (HTTP): {stats.get('Suspicious (4xx)', 0) + stats.get('Server Errors (5xx)', 0)}\n"
            
            # Always show these to confirm checks ran
            preview += f"Brute Force IPs: {len(brute_force)}\n"
            preview += f"High Volume IPs: {len(high_vol)}\n"
            preview += f"IDS Alerts: {len(ids_alerts)}\n"
            preview += f"Forbidden File Access: {len(forbidden)}\n"
            preview += f"Suspicious Agents: {len(suspicious)}\n"
            preview += f"Potential Exfiltration: {len(exfil)}\n"

            high_risk = len(risk[risk['risk_score'] > 50]) if not risk.empty else 0
            preview += f"CRITICAL/HIGH Risk IPs: {high_risk}\n"
            preview += "\n"

            preview += "[CHAIN OF CUSTODY (Last 5 Actions)]\n"
            coc_lines = coc.strip().split('\n')
            # Filter distinct actions or just show last few valid lines
            valid_coc = [line for line in coc_lines if line.strip() and not line.startswith('=')]
            for line in valid_coc[-5:]:
                preview += f"{line}\n"
            
            preview += "\n[FULL ANALYSIS]\n"
            preview += "(See exported report for comprehensive details on Brute Force, Exfiltration, etc.)"

            self.txt_report_preview.delete("0.0", "end")
            self.txt_report_preview.insert("0.0", preview)
        else:
            self.txt_report_preview.delete("0.0", "end")
            self.txt_report_preview.insert("0.0", "Load and analyze a file first.")

    def export_report(self):
        if not self.log_analyzer:
            messagebox.showwarning("Error", "No analysis data to report.")
            return

        coc = self.evidence_handler.get_coc_text()
        
        ids_alerts = pd.DataFrame()
        if hasattr(self.log_analyzer, 'detect_ids_alerts'):
            ids_alerts = self.log_analyzer.detect_ids_alerts()

        # Integrity Check
        integrity_verified = False
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

        results = {
            'stats': self.log_analyzer.get_traffic_summary(),
            'high_volume': self.log_analyzer.detect_high_volume_ips(),
            'forbidden': self.log_analyzer.detect_forbidden_files(),
            'errors': self.log_analyzer.analyze_status_codes(),
            'suspicious': self.log_analyzer.detect_suspicious_user_agents(),
            'exfiltration': self.log_analyzer.detect_large_responses(threshold_bytes=1000000),
            'brute_force': self.log_analyzer.detect_brute_force(),
            'ids_alerts': ids_alerts,
            'risk_score': self.log_analyzer.calculate_risk_score()
        }
        
        # 1. Gather Metadata for PDF Report
        try:
            file_size = os.path.getsize(self.current_file_path)
            hostname = socket.gethostname()
            
            scan_end = datetime.datetime.now()
            duration = "N/A"
            if self.scan_start_time:
                delta = scan_end - self.scan_start_time
                duration = str(delta).split('.')[0] # HH:MM:SS
                
            # 2. Generate PDF Report
            path = self.reporter.generate_pdf_report(
                case_id=self.evidence_handler.case_id, 
                coc_text=coc, 
                file_hash=self.file_hash, 
                analysis_results=results, 
                integrity_verified=integrity_verified,
                examiner_name=self.evidence_handler.investigator,
                file_path_evidence=self.current_file_path,
                file_size=file_size,
                scan_duration=duration,
                egress_hash=current_hash if integrity_verified else "HASH_MISMATCH"
            )

            # Optional: Generate Text backup (per requirements "A CSV/JSON version can be generated alongside")
            # self.reporter.generate_text_report(self.evidence_handler.case_id, coc, self.file_hash, results, integrity_verified)
            
            if path:
                messagebox.showinfo("Report Generated", f"PDF Report saved to:\n{path}")
            else:
                messagebox.showerror("Error", "Failed to generate PDF report.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to gather report metadata: {e}")

if __name__ == "__main__":
    app = App()
    app.mainloop()
