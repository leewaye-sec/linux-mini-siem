| Log Entry          | Class                | Subclass            | Parse Complete | Detector Complete |
| ------------------ | -------------------- | ------------------- | -------------- | ----------------- |
| Failed password    | AUTHENTICATION       | FAILED_LOGIN        | X              | X                 |
| Accepted password  | AUTHENTICATION       | SUCCESSFUL_LOGIN    | X              | X                 |
| Invalid user       | AUTHENTICATION       | INVALID_USER_LOGIN  | X              | X                 |
| useradd            | USER_MANAGEMENT      | USER_CREATED        | X              | X                 |
| userdel            | USER_MANAGEMENT      | USER_DELETED        | X              | X                 |
| password changed   | USER_MANAGEMENT      | PASSWORD_CHANGED    | X              | X                 |
| usermod -aG sudo   | PRIVILEGE_ESCALATION | USER_ADDED_TO_SUDO  | X              | X                 |
| usermod -aG wheel  | PRIVILEGE_ESCALATION | USER_ADDED_TO_WHEEL | X              | X                 |
| cat /etc/shadow    | CREDENTIAL_ACCESS    | SHADOW_FILE_ACCESS  | X              | X                 |
| cat /etc/passwd    | CREDENTIAL_ACCESS    | PASSWD_FILE_ACCESS  | X              | X                 |
| apt install netcat | SUSPICIOUS_COMMAND   | NETCAT_INSTALLATION | X              | X                 |
| apt install nmap   | SUSPICIOUS_COMMAND   | NMAP_INSTALLATION   | X              | X                 |
| curl payload       | SUSPICIOUS_COMMAND   | CURL_DOWNLOAD       | X              | X                 |
| wget payload       | SUSPICIOUS_COMMAND   | WGET_DOWNLOAD       | X              | X                 |
| scp payload        | SUSPICIOUS_COMMAND   | SCP_FILE_TRANSFER   | X              | X                 |
| tar payload        | SUSPICIOUS_COMMAND   | TAR_ARCHIVE_CREATION| X              | X                 |
| auditd stopped     | DEFENSE_EVASION      | AUDITD_STOPPED      | X              | X                 |
| firewalld stopped  | DEFENSE_EVASION      | FIREWALL_STOPPED    | X              | X                 |
| telnet enabled     | DEFENSE_EVASION      | TELNET_ENABLED      | X              | X                 |
