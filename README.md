# LogDetect - Digital Forensics Log Analysis Tool

LogDetect is a GUI-based forensic tool designed to analyze web server and security logs. It provides a modern interface for investigators to detect anomalies, maintain a chain of custody, and visualize security threats.

## 📦 Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/HeinreichMorphine/LogDetect.git
    cd LogDetect
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 📂 Web Server Log Analysis Forensic Scenarios
To run the test cases, use the provided `Apache.log` or datasets from **Loghub**:
[https://github.com/logpai/loghub/tree/master/Apache](https://github.com/logpai/loghub/tree/master/Apache)

*   **Scenario 1**: Webserver Attack (`Apache.log`)
*   **Scenario 2**: Brute Force & IDS (`scenario2/gather/acme_mail/logs` & `scenario2/gather/cloud_share/logs/suricata`)

## 🚀 How to Run

Launch the application using Python:

```bash
python main.py
```

Or simply double-click **`run_logdetect.bat`** to start the tool automatically.

## 🧪 Test Cases

Follow these steps to verify the tool's functionality with the provided scenario logs.

### Scenario 1: Web Server Attack (Apache)

1.  Open **LogDetect**.
2.  In the "Evidence Acquisition" tab, enter a Case ID and Investigator Name, then click **Set Case Details**.
3.  Click **Select Log File**.
4.  Navigate to: `Downloads > FORENSIC`.
5.  Select: `Apache.log`.
6.  Go to the **Analysis Dashboard** tab.
7.  Click **"Dir Traversal"** or **"Vuln Scans"** to view detected attacks from IPs like `63.203.254.140`.


## 📊 Features
*   **Instant Dashboard**: "Analysis Dashboard" loads instantly thanks to background pre-fetching.
*   **Dual Reporting**: Export professional **PDF Reports** (Executive Summary) or raw **Text Reports** (Full Data) with one click.
*   **Visual Feedback**: Real-time progress bar during evidence scanning.
*   **Smart Caching**: Persistent `geo_cache.json` caches IP geolocation data, making re-analysis lightning fast.
*   **Chain of Custody**: Automatic SHA256 hashing and action logging for forensic integrity.
*   **Threat Detection**:
    *   **High Volume IPs**: Detects DoS/Scanning attempts (Whitelisted IPs excluded).
    *   **Risk Scoring**: Prioritizes threats based on error rates and attack patterns.
    *   **Attack Signatures**: Identifies Directory Traversal and Vulnerability Scanning.

## 🔧 Technical Implementation

LogDetect is built using a modular Python architecture to ensure maintainability and forensic integrity.

### 🏗️ Architecture Overview
*   **GUI (`gui/app.py`)**: Built with **CustomTkinter** for a modern, high-DPI compatible interface. It handles user interactions, manages background threads for geolocation pre-fetching, and updates the real-time visual progress bar.
*   **Analysis Engine (`modules/analyzer.py`)**: The core logic engine. It uses **Pandas** DataFrames for high-performance memory-based processing.
    *   **Parsing**: Uses Regex to normalize raw logs (Apache, Syslog, Suricata) into structured data.
    *   **Detection**: Applies heuristic filters to identify DOS attacks, scanning patterns, and high-risk status codes (4xx/5xx).
    *   **Caching**: Implements a persistent JSON disk cache (`save_cache`, `load_cache`) to store Geolocation data, significantly speeding up subsequent analyses.
*   **Evidence Handler (`modules/evidence.py`)**: Ensures forensic admissibility.
    *   **Hashing**: Calculates SHA-256 hashes of files pre- and post-analysis to prove data integrity.
    *   **Chain of Custody**: Logs every user action (acquisition, transfer, analysis) with timestamps.
*   **Reporting (`modules/reporter.py`)**:
    *   **PDF Generation**: Uses **ReportLab** to craft professional forensic reports with tables and metadata.
    *   **Text Generation**: Exports raw data for external processing.

## 🐛 Reporting Bugs & Updates

### Found a Bug?
If you encounter any issues or bugs, please report them to the developer or open an Issue on the GitHub repository.

### Updating the Tool
To ensure you have the latest features and bug fixes, run the following command in the project directory:

```bash
git pull origin main
```
