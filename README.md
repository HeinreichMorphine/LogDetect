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

## 🐛 Reporting Bugs & Updates

### Found a Bug?
If you encounter any issues or bugs, please report them to the developer or open an Issue on the GitHub repository.

### Updating the Tool
To ensure you have the latest features and bug fixes, run the following command in the project directory:

```bash
git pull origin main
```
