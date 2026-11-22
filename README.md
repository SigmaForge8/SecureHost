
# SecureHost
### Linux Host-Based Security Monitoring and Intrusion Detection System (HIDS)

SecureHost is a Python-based Linux Host-Based Intrusion Detection System (HIDS) developed as an academic Operating Systems project.

The project aims to monitor important host activities, collect system events, identify potentially suspicious behavior, and generate security alerts.

## Project Objectives

- Monitor Linux system processes and resource usage.
- Collect and store host security events.
- Detect suspicious activity using configurable detection rules.
- Monitor file integrity and authentication activity.
- Monitor network activity.
- Provide a dashboard for viewing security events and alerts.

## Technology Stack

- Python
- Linux
- psutil
- SQLite
- Flask (planned dashboard component)
- Git and GitHub

## Current Implementation Status

| Component                                  | Status |
|---                                         |---|
| Standardized security events               | Implemented |
| Linux process monitoring                   | Implemented and tested |
| CPU usage detection (R05)                  | Implemented and tested |
| SQLite event storage                       | Implemented and tested |
| SQLite alert storage                       | Implemented and tested |
| File integrity monitoring                  | Team development |
| Authentication monitoring                  | Team development |
| Network monitoring                         | Team development |
| Flask dashboard                            | Team development |

## Verified Detection Rule

### R05 — High CPU Usage Detection

The detection engine monitors process CPU usage.

Current rule configuration:

- CPU threshold: 80%
- Consecutive samples required: 3
- Collection interval: 5 seconds
- Alert deduplication: Enabled

A controlled CPU-load test successfully triggered an R05 alert.

Example alert:

```text
[ALERT] R05 | Low | Process 6386 exceeded 80% CPU for 3 consecutive samples
```

The generated alert was also verified in the SQLite database.

## Project Structure

```text
SecureHost/
├── collectors/
├── core/
├── dashboard/
├── storage/
├── config/
├── tests/
├── docs/
├── requirements.txt
├── README.md
├── .gitignore
└── run.py
```

## Installation

Clone the repository:

```bash
git clone https://github.com/SigmaForge8/SecureHost.git
cd SecureHost
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run SecureHost

```bash
python run.py
```

Stop monitoring with:

```text
CTRL + C
```

## Database

SecureHost uses SQLite to store collected events and generated alerts.

Database location:

```text
storage/securehost.db
```

The local database is generated during execution and is not committed to GitHub.

## Development Team

This project is developed collaboratively by a three-member team.

Development is organized using separate Git branches and GitHub collaboration.

## Project Purpose

The goal of SecureHost is to demonstrate practical knowledge of Linux system monitoring, process management, event collection, rule-based threat detection, and security event storage.
