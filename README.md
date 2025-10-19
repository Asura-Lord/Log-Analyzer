

# Log Analyzer for Suspicious Activity

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Status](https://img.shields.io/badge/Status-Completed-green)

**“Secure the system before the hackers do...”** 🔒

---

## Overview
**Log Analyzer** is a Python tool that scans system logs to detect **failed login attempts**, **brute-force attacks**, and other suspicious activity. It simulates a **mini SIEM (Security Information and Event Management) tool** and is perfect for cybersecurity learning, SOC labs, and incident response training.

---

## Features
- Detect multiple failed login attempts from a single IP
- Identify potential brute-force attacks
- Count failed attempts per IP and generate reports
- Create **visual charts** showing top attackers and failed attempts
- Export analysis results to **CSV** for further review
- Lightweight CLI interface

---

## How It Works
1. Input a log file (e.g., `auth.log`, `syslog`, or custom logs)  
2. Scan each line for **failed login attempts**  
3. Extract IP addresses using **regex**  
4. Count failed attempts per IP  
5. Flag IPs with more than a threshold (e.g., 5) as suspicious  
6. Generate **summary report** and optional **charts** for visualization

---

## Screenshots
Here’s how the tool looks in action:

** Terminal :**  
<img width="1035" height="421" alt="Screenshot 2025-10-19 134102" src="https://github.com/user-attachments/assets/eda44e53-a364-4dcd-8423-a59ed08cb825" />

**Visual Chart 1 Example:**  

<img width="991" height="708" alt="Screenshot 2025-10-19 134025" src="https://github.com/user-attachments/assets/2be85019-de99-4219-b28d-11a69a6a3f75" />


**Visual Chart 2 Example:**  

<img width="1249" height="573" alt="Screenshot 2025-10-19 134034" src="https://github.com/user-attachments/assets/d342114f-8fc8-4bfc-9c1a-69142554edb0" />




---

## Installation
Make sure you have **Python 3.10+** installed.

Install dependencies:

```bash
pip install -r requirements.txt
````

---

## Usage

Run the tool:

```bash
python main.py
```

Follow the prompts:

* Enter the path to your log file
* View detected suspicious IPs and summary report
* Visual charts (if enabled) will display top offenders and trends

---

## Tech Stack

* **Python 3.10+**
* **Libraries:** `pandas`, `matplotlib`, `re`, `collections`

---

## Sample Output

```
Top 5 IPs with failed login attempts:
192.168.1.15 - 12 attempts
10.0.0.5    - 8 attempts
172.16.0.9  - 6 attempts
...
```

---

## Use Cases

* SOC lab exercises
* Security incident simulations
* Learning regex and log analysis
* Practicing Python data visualization

---

## License

MIT License - Asura Lord

```

