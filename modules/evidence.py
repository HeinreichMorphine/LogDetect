import hashlib
import json
import os
import datetime

class EvidenceHandler:
    def __init__(self):
        self.case_id = "UNKNOWN"
        self.investigator = "UNKNOWN"
        self.coc_log = []

    def set_case_details(self, case_id, investigator):
        """Set the current case details."""
        self.case_id = case_id
        self.investigator = investigator

    def calculate_hash(self, file_path, algorithm='sha256'):
        """Calculate the hash of a file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        file_hash = hash_func.hexdigest()
        self.log_action(f"Calculated {algorithm} hash for {os.path.basename(file_path)}: {file_hash}")
        return file_hash

    def log_action(self, action, description=""):
        """Log an action to the Chain of Custody."""
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "case_id": self.case_id,
            "investigator": self.investigator,
            "action": action,
            "description": description
        }
        self.coc_log.append(entry)

    def save_coc(self, output_path):
        """Save the Chain of Custody log to a JSON file."""
        try:
            with open(output_path, "w") as f:
                json.dump(self.coc_log, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving CoC: {e}")
            return False

    def get_coc_text(self):
        """Return CoC log as a formatted string."""
        text = f"Chain of Custody Log - Case: {self.case_id}\n"
        text += f"Investigator: {self.investigator}\n"
        text += "=" * 50 + "\n"
        for entry in self.coc_log:
            text += f"[{entry['timestamp']}] {entry['action']}\n"
            if entry['description']:
                text += f"Detail: {entry['description']}\n"
            text += "-" * 20 + "\n"
        return text

    def preserve_evidence(self, source_path):
        """Create a forensic copy of the evidence in a secure case folder."""
        try:
            case_dir = os.path.join("cases", self.case_id)
            if not os.path.exists(case_dir):
                os.makedirs(case_dir)
            
            filename = os.path.basename(source_path)
            dest_path = os.path.join(case_dir, f"EVIDENCE_{filename}")
            
            # Simple binary copy
            with open(source_path, 'rb') as src, open(dest_path, 'wb') as dst:
                dst.write(src.read())
                
            self.log_action("Evidence Preserved", f"Copied {source_path} to {dest_path}")
            return dest_path
        except Exception as e:
            self.log_action("Preservation Failed", str(e))
            raise e

    def hash_string(self, content):
        """Calculate hash of a string content (for report verification)."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
