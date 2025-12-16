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

## � Web Server Log Analysis Forensic Scenarios
To run the test cases, download the **Analysis Forensic Scenarios** dataset from Zenodo:
[https://zenodo.org/records/5779411](https://zenodo.org/records/5779411)

*   **Scenario 1**: Webserver Attack (`scenario1/gather/webserver/logs/apache2`)
*   **Scenario 2**: Brute Force & IDS (`scenario2/gather/acme_mail/logs` & `scenario2/gather/cloud_share/logs/suricata`)

## �🚀 How to Run

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
4.  Navigate to: `Downloads > FORENSIC > scenario1 > gather > webserver > logs > apache2`.
5.  Select: `cloud.company.cyberrange.at-access.log`.
6.  Go to the **Analysis Dashboard** tab.
7.  Click **Check High Volume IPs** or **Suspicious Agents** to view stats and charts.

### Scenario 2: Brute Force & IDS Alerts

#### Case A: Authentication Logs (Syslog)
1.  Click **Select Log File** again.
2.  Navigate to: FORENSIC\scenario2\gather\acme_mail\logs`.
3.  Select: `auth.log`.
4.  On the **Analysis Dashboard**, click **Brute Force**.
5.  *Result*: You should see detection of IP `192.42.1.22` with high authentication failures.

#### Case B: Intrusion Detection (Suricata)
1.  Click **Select Log File**.
2.  Navigate to: FORENSIC\scenario2\gather\cloud_share\logs\suricata`.
3.  Select: `fast.log`.
4.  On the **Analysis Dashboard**, click **Check IDS Alerts**.
5.  *Result*: You will see a list of intrusion alerts (e.g., `SURICATA TLS invalid handshake`) and a chart of top source IPs.

## 📊 Features
*   **Chain of Custody**: Automatic SHA256 hashing and action logging.
*   **Visualizations**: Downloadable charts for threat analysis.
*   **Reporting**: Export findings to a text report with one click.

## 🐛 Reporting Bugs & Updates

### Found a Bug?
If you encounter any issues or bugs, please report them to the developer or open an Issue on the GitHub repository.

### Updating the Tool
To ensure you have the latest features and bug fixes, run the following command in the project directory:

```bash
git pull origin main
```
