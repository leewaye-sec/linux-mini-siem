# Mini SIEM

A lightweight Python-based Security Information and Event Management (SIEM) platform designed to analyze Linux system logs, identify suspicious activity, and generate actionable security findings.

This project focuses on core detection engineering concepts, including log parsing, event correlation, threat detection, and security reporting.

---

## Project Goals

The primary goals of this project are:

* Parse Linux system logs
* Detect common security events
* Correlate related events
* Generate structured findings
* Export results as JSON reports
* Explore SOC and detection engineering workflows

---

## Planned Features

### Log Ingestion

* Authentication logs (`auth.log`)
* System logs (`syslog`)
* Custom log file support

### Detection Rules

* SSH brute force attempts
* Successful login after multiple failures
* New user creation
* Sudo privilege usage
* Service modifications
* Authentication anomalies

### Event Correlation

* Multiple failed logins from a single source
* Account compromise indicators
* Suspicious privilege escalation activity

### Reporting

* Terminal output
* JSON report generation
* Audit summaries
* Severity classifications

---

## Planned Architecture

```text
Log Sources
     |
     v
Log Parser
     |
     v
Detection Engine
     |
     +--> SSH Detections
     +--> User Activity Detections
     +--> Privilege Escalation Detections
     |
     v
Event Correlation
     |
     v
Reporting Engine
     |
     +--> Console Output
     +--> JSON Reports
```

---

## Project Structure

```text
mini-siem/
├── src/
│   ├── main.py
│   ├── parser.py
│   ├── detectors.py
│   ├── reporting.py
│   └── rules.py
├── docs/
├── examples/
├── reports/
├── screenshots/
├── tests/
├── requirements.txt
└── README.md
```

---

## Planned Detection Rules

| Detection                       | Severity |
| ------------------------------- | -------- |
| SSH Brute Force                 | High     |
| Successful Login After Failures | Critical |
| New User Creation               | Medium   |
| Sudo Activity                   | Low      |
| Service Modification            | Medium   |
| Unknown Authentication Failures | Medium   |

---

## Example Finding

```json
{
  "event": "SSH_BRUTE_FORCE",
  "source_ip": "192.168.1.100",
  "attempt_count": 15,
  "severity": "HIGH"
}
```

---

## Technologies

* Python 3
* Linux
* JSON
* Regular Expressions
* Logging
* Security Event Analysis

---

## Learning Objectives

This project is intended to develop practical experience with:

* Detection engineering
* Security operations (SOC)
* Log analysis
* Threat detection
* Event correlation
* Security reporting
* Incident investigation workflows

---

## Planned Future Enhancements

* MITRE ATT&CK mapping
* Sigma-style detection rules
* HTML reporting
* Docker deployment
* Web dashboard
* Real-time log monitoring

---

## Status

🚧 Initial development phase

Current focus:

* Repository setup
* Log parser development
* Initial SSH detection rules

---

## License

MIT License

