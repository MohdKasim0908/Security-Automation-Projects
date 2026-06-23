# Failed Login Detector

## Overview

Failed Login Detector is a Python-based security automation tool that analyzes authentication logs and identifies IP addresses responsible for failed login attempts.

The tool extracts IP addresses from log files, counts failed login attempts, flags suspicious activity based on a configurable threshold, and generates a security report.

---

## Features

* Parse authentication log files
* Extract IP addresses using Regular Expressions (Regex)
* Count failed login attempts per IP
* Detect suspicious IP addresses
* Generate a structured security report
* Configurable alert threshold
* Error handling for missing log files

---

## Technologies Used

* Python 3
* Regular Expressions (`re`)
* File Handling
* Exception Handling
* Collections (`Counter`)

---

## Project Structure

```text
failed_login_detector/
│
├── auth.log
├── detector.py
├── report.txt
└── README.md
```

---

## How It Works

1. Reads authentication logs from `auth.log`
2. Identifies failed login entries
3. Extracts IP addresses
4. Counts occurrences for each IP
5. Flags suspicious IPs based on the alert threshold
6. Generates a report

---

## Sample Input

```text
Failed login from 192.168.1.10
Failed login from 192.168.1.10
Failed login from 10.0.0.5
Successful login from 10.0.0.8
Failed login from 192.168.1.10
```

---

## Sample Output

```text
Suspicious IP Addresses
-----------------------
192.168.1.10 -> 3 Attempts

Other IP Addresses
------------------
10.0.0.5 -> 1 Attempt
```

---

## Skills Demonstrated

* Python Automation
* Security Log Analysis
* Regular Expressions
* Data Processing
* Security Monitoring Concepts
* Report Generation

---

## Future Improvements

* Username extraction
* Timestamp analysis
* JSON report generation
* Multiple log file support
* Directory scanning
* Email alerting
* AWS CloudWatch log integration

---

## Author

Mohammed Kasim R 

Aspiring Cloud Security Engineer | RHCSA Certified | Python & AWS Enthusiast
