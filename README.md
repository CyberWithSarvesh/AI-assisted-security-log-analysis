# AI-Assisted Security Log Analysis

An end-to-end security analytics pipeline that parses Apache HTTP access logs, engineers source-IP behavioral features, detects anomalous activity using machine learning, and converts detected anomalies into analyst-oriented security alerts with severity scoring and MITRE ATT&CK context.

## Project Overview

Security teams often receive large volumes of web-server logs that are difficult to investigate manually.

This project demonstrates a lightweight security analytics workflow that transforms raw Apache HTTP access logs into prioritized security findings.

The pipeline performs four major stages:

1. Apache log parsing
2. Source-IP behavioral feature engineering
3. Machine-learning anomaly detection
4. Security alert generation and MITRE ATT&CK mapping

The goal is to demonstrate how security telemetry can be transformed into actionable investigation data rather than simply reporting raw log events.

---

## Architecture

```text
Apache Access Logs
        |
        v
+---------------------+
|   Log Parser        |
|   parse_logs.py     |
+----------+----------+
           |
           v
+--------------------------+
| Feature Engineering      |
| feature_engineering.py   |
+------------+-------------+
             |
             v
+--------------------------+
| Isolation Forest ML       |
| anomaly_detection.py     |
+------------+-------------+
             |
             v
+--------------------------+
| Alert Generation         |
| alert_generator.py       |
+------------+-------------+
             |
             v
+--------------------------+
| Security Alerts          |
| Severity + MITRE ATT&CK  |
+--------------------------+

---

Detection Pipeline
1. Apache Log Parsing

parse_logs.py processes Apache Combined Log Format records and extracts:

Source IP
Timestamp
HTTP method
Requested path
HTTP status code
Response size
Referrer
User agent

The parser successfully processed 9,999 of 10,000 records in the project dataset.

The parser also identifies malformed records so they can be reviewed separately.

2. Behavioral Feature Engineering

feature_engineering.py aggregates HTTP activity by source IP.

The following behavioral features are generated:

Feature	Description
request_count	Total HTTP requests from the source IP
error_count	Number of HTTP error responses
unique_paths	Number of distinct requested paths
suspicious_path_count	Requests matching security-relevant path patterns
error_rate	HTTP errors divided by total requests
scan_path_ratio	Unique requested paths divided by total requests

Security-relevant path patterns include indicators such as:

/admin
/login
/wp-admin
/phpmyadmin
/config
/passwd
/etc/passwd
/.env
/.git
cmd
shell
cgi-bin
3. Machine Learning Anomaly Detection

The project uses an Isolation Forest model to identify source IPs whose behavioral characteristics differ from the rest of the observed traffic.

Model configuration
Algorithm: Isolation Forest
Estimators: 200
Random state: 42
Input features: 6 behavioral features

The model produces:

Anomaly label
Anomaly score
Normal / Anomaly classification

Lower anomaly scores generally indicate more unusual observations.

4. Security Alert Generation

Detected anomalies are passed to alert_generator.py.

The alert-generation stage adds security context including:

Risk level
Detection reasons
Request volume
HTTP error behavior
Path diversity
Suspicious path activity
Scan behavior
MITRE ATT&CK mapping
Recommended analyst action
Risk levels
Risk Level	Purpose
High	Prioritize investigation
Medium	Investigate unusual behavior
Low	Review during normal SOC triage

Severity is determined using behavioral indicators such as request volume, error rate, path diversity, suspicious paths, and scanning behavior.

MITRE ATT&CK Context

The alert-generation stage maps qualifying behaviors to relevant MITRE ATT&CK techniques.

Examples include:

T1595 — Active Scanning

Used when source-IP behavior demonstrates significant path diversity and request activity consistent with scanning behavior.

T1190 — Exploit Public-Facing Application

The project treats this as a potential mapping when suspicious paths, meaningful request volume, and HTTP errors provide supporting indicators.

The pipeline intentionally does not automatically claim that exploitation occurred based only on suspicious paths.

Alerts without sufficient evidence receive:

No direct MITRE technique assigned; analyst review required

This distinction is important because behavioral indicators should not automatically be treated as confirmed exploitation.

Project Results

The pipeline was executed against a 10,000-line Apache HTTP access-log dataset.

Parsing
Total HTTP log events: 10,000
Successfully parsed: 9,999
Failed to parse: 1
Feature Engineering
HTTP events processed: 9,999
Unique source IPs: 1,753
Anomaly Detection
Source IPs analyzed: 1,753
Anomalies identified: 199
Normal source IPs: 1,554
Anomaly rate: 11.35%
Anomaly Statistics

Among the detected anomalies:

Mean request count: 25.503
Mean error count: 1.106
Mean unique paths: 16.623
Mean suspicious-path count: 0.422
Mean error rate: 0.260
Mean scan-path ratio: 0.775

These results demonstrate how source-IP behavioral features can be used to prioritize unusual web traffic for further investigation.

Example Detection Indicators

The alerting pipeline can identify behaviors such as:

High request volume
High HTTP error rate
Large numbers of unique requested paths
Multiple suspicious path patterns
High unique-path-to-request ratio
Significant deviation from peer source-IP behavior

Example MITRE context can include:

T1595 - Active Scanning

or, when supporting indicators are present:

T1190 - Exploit Public-Facing Application (potential)
Repository Structure
AI-assisted-security-log-analysis/
|
├── src/
│   ├── parse_logs.py
│   ├── feature_engineering.py
│   ├── anomaly_detection.py
│   └── alert_generator.py
|
├── data/
│   └── apache_logs.txt
|
├── output/
│   ├── ip_features.csv
│   ├── anomaly_results.csv
│   └── security_alerts.csv
|
├── screenshots/
|
├── .gitignore
├── requirements.txt
└── README.md
Technologies
Python
Pandas
NumPy
Scikit-learn
Regular Expressions
Isolation Forest
MITRE ATT&CK
Apache HTTP access logs
Git / GitHub
Installation

Clone the repository:

git clone https://github.com/CyberWithSarvesh/AI-assisted-security-log-analysis.git
cd AI-assisted-security-log-analysis

Install dependencies:

pip install -r requirements.txt
Running the Pipeline
Step 1 — Parse Apache logs
python src/parse_logs.py
Step 2 — Generate behavioral features
python src/feature_engineering.py
Step 3 — Run anomaly detection
python src/anomaly_detection.py
Step 4 — Generate security alerts
python src/alert_generator.py

Generated outputs are written to:

output/
Outputs
ip_features.csv

Contains source-IP behavioral features used by the machine-learning model.

anomaly_results.csv

Contains:

Source IP
Behavioral features
Anomaly label
Anomaly score
Normal / Anomaly classification
security_alerts.csv

Contains analyst-oriented security findings including:

Source IP
Risk level
Anomaly score
Detection reasons
MITRE ATT&CK mapping
Recommended action
Security Engineering Concepts Demonstrated

This project demonstrates practical concepts relevant to Security Operations and Cybersecurity Analytics:

Security log analysis
Apache HTTP log parsing
Network behavior profiling
Feature engineering
Unsupervised machine learning
Anomaly detection
Security alert triage
Risk scoring
MITRE ATT&CK mapping
SOC-oriented investigation workflows
Security automation
Python-based data analysis
Limitations

This project is intended as a security analytics demonstration and should not be treated as a production detection system.

Important limitations include:

Anomaly detection does not prove malicious activity.
Threshold-based indicators can produce false positives.
MITRE ATT&CK mappings are contextual rather than proof of attacker intent.
IP-based aggregation can hide activity distributed across multiple source addresses.
Additional telemetry would be required for stronger detection confidence.

Production deployment would require additional validation, tuning, historical baselines, enrichment, and correlation with other security telemetry.

Future Improvements

Potential improvements include:

Real-time log ingestion
Streaming anomaly detection
IP reputation enrichment
GeoIP enrichment
User-agent profiling
Time-window based behavioral features
Automated threat-intelligence enrichment
SIEM integration
SOC dashboard
Automated investigation playbooks
Model evaluation and threshold tuning
Containerized deployment
CI/CD testing
Author

Sarvesh Batham

Cybersecurity professional focused on:

Identity & Access Management
Security Operations
Cybersecurity Analytics
Cloud Security
Security Automation
Machine Learning for Security


Disclaimer**

This project is intended for educational, research, and defensive security purposes.
The presence of anomalous behavior does not by itself establish malicious intent or successful exploitation. Security findings should be validated through appropriate investigation and additional telemetry.
