# SSH Access & Failed Login Analyzer

A Python-based security automation tool that analyzes SSH authentication logs to detect failed login attempts, identify suspicious IP addresses, track successful logins, and generate detailed security reports.

This project demonstrates practical Python automation skills commonly used in cybersecurity, Linux system administration, and Security Operations Center (SOC) environments.

---

## Features

* Analyze multiple SSH log files automatically
* Detect failed login attempts
* Track successful user logins
* Extract attacker IP addresses
* Identify targeted usernames
* Detect suspicious IPs using a configurable alert threshold
* Generate a structured security report
* Summarize authentication activity and attack statistics

---

## Technologies Used

* Python 3
* Regular Expressions (Regex)
* File Handling
* Exception Handling
* Collections (`Counter`)
* OS Module
* Datetime Module

---

## Project Structure

```text
ssh_access_failed_login_analyzer/
│
├── logs/
│   ├── ssh1.log
│   ├── ssh2.log
│   └── ssh3.log
│
├── Reports/
│   └── Report.txt
│
├── analyzer.py
└── README.md
```

---

## Report Includes

* Files analyzed
* Suspicious IP addresses
* Top attacking IPs
* Most targeted usernames
* Successful login users
* Total failed logins
* Total successful logins
* Number of unique attacker IPs
* Number of targeted users
* Top attacking IP summary
* Most targeted user summary

---

## Sample Workflow

```text
SSH Log Files
        │
        ▼
Read All Log Files
        │
        ▼
Extract Users & IPs using Regex
        │
        ▼
Analyze Authentication Activity
        │
        ▼
Detect Suspicious IPs
        │
        ▼
Generate Security Report
```

---

## Skills Demonstrated

* Python Automation
* Log File Analysis
* Security Event Monitoring
* Regular Expressions
* Data Processing
* Report Generation
* Linux Log Analysis Fundamentals

---

## Future Improvements

* JSON report generation
* Command-line arguments
* Configurable alert threshold
* Support for additional Linux log formats
* Unit tests
* AWS CloudWatch log integration

---

## Author

Mohammed Kasim

RHCSA Certified | Python Automation | AWS & Cloud Security Enthusiast
