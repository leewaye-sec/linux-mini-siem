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
     +--> Authentication Detections
     +--> User Management Detections
     +--> Privilege Escalation Detections
     +--> Defense Evasion Detections
     +--> Credential Access Detections
     +--> Suspicious Command Detections
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
│   ├── linuxMiniSIEM.py
│   └── SIEM_CLASSES/
│       ├── SIEMDetectionEngine.py
│       ├── SIEMLogParser.py
│       ├── StandardizedDataStructures.py
│       └── DETECTORS/
│           ├── __init__.py
│           ├── DetectorBaseDefinition.py
│           ├── AuthenticationEvents.py
│           ├── CredentialAccessEvents.py
│           ├── DefenseEvasionEvents.py
│           ├── PrivilegeEscalationEvents.py
│           ├── SuspiciousCommandEvents.py
│           └── UserManagementEvents.py
├── docs/
│   └── detection-matrix.md
├── examples/
│   ├── benign_auth.log
│   ├── compromised_host.log
│   ├── detection_validation.log
│   ├── insider_activity.log
│   └── sample_auth.log
├── reports/
├── screenshots/
├── tests/
├── requirements.txt
└── README.md
```

---

## Planned Detection Rules

### Authentication Events

| Detection                       | Severity | Reason                                       |
| ------------------------------- | -------- | -------------------------------------------- |
| Invalid User Login              | LOW      | Reconnaissance                               |
| Failed Login                    | INFO     | Common event, primarily used for correlation |
| SSH Brute Force                 | HIGH     | Active attack                                |
| Successful Login                | INFO     | Normal event, primarily used for correlation |
| Successful Login After Failures | CRITICAL | Potential compromise                         |
| Root Login Success              | CRITICAL | High-value account access                    |

### User Management Events

| Detection        | Severity | Reason                              |
| ---------------- | -------- | ----------------------------------- |
| User Created     | MEDIUM   | Administrative change / persistence |
| User Deleted     | MEDIUM   | Account manipulation                |
| Password Changed | MEDIUM   | Account manipulation                |

### Privilege Escalation Events

| Detection                 | Severity | Reason               |
| ------------------------- | -------- | -------------------- |
| User Added To sudo Group  | HIGH     | Privilege escalation |
| User Added To wheel Group | HIGH     | Privilege escalation |

### Credential Access Events

| Detection          | Severity | Reason                              |
| ------------------ | -------- | ----------------------------------- |
| Shadow File Access | HIGH     | Credential access                   |
| Passwd File Access | LOW      | Usually public, but worth recording |

### Defence Evasion Events

| Detection        | Severity | Reason                            |
| ---------------- | -------- | --------------------------------- |
| Auditd Stopped   | HIGH     | Disables auditing                 |
| Firewall Stopped | HIGH     | Reduces host protection           |
| Telnet Enabled   | HIGH     | Introduces insecure remote access |

### Suspicious Commands Events

| Detection           | Severity | Reason                                              |
| ------------------- | -------- | --------------------------------------------------- |
| Nmap Installation   | MEDIUM   | Legitimate admin tool but useful for reconnaissance |
| TAR Archive Creation| MEDIUM   | Legitimate admin tool but useful for data staging   |
| Netcat Installation | HIGH     | Common attacker tooling                             |
| SCP File Transfer   | HIGH     | Potential data exfiltration                         |
| Curl Download       | HIGH     | Potential payload retrieval                         |
| Wget Download       | HIGH     | Potential payload retrieval                         |


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

