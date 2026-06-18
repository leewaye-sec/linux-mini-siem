#!/usr/local/bin/python3
#==========================================================================
#
#           File : SIEMLogParser.py
#        Project : Mini-SIEM
#    Description : Class definition for log parser
#                  Parse the logs to populate / create event (dataclass)
#
#==========================================================================
#----------------
# Imports
#----------------
import re
from datetime import datetime

# Import dataclass LogEvent
from StandardizedDataStructures import LogEvent

#----------------
# Class Definition
#----------------
class siemLogParser:
    # Build out the actual parsing
    #   line: str [include type hints for line]
    #   -> LogEvent | None [define return types]
    def parseLogLine(self, line: str) -> LogEvent | None:

        #=======================
        # Parse out common log information
        #   Common : timestampe, hostname, entry type
        #   Once entry type is determined, proceed for type-specific parsing
        #=======================
        # Split the line into array
        line_split = line.split()

        # Timestamp
        #   Isolate and then remove
        log_timestamp = datetime.strptime(' '.join(line_split[:3]), "%b %d %H:%M:%S")
        del line_split[:3]

        # Hostname
        log_hostname = line_split[0]
        del line_split[0]

        # Log Entry Type
        #   Remove the unnecessary extra from the entry (e.g. sshd[7394]: --> SSHD)
        log_entry = re.sub(r"(\[\d+\]):", "", line_split[0]).upper()
        del line_split[0]

        # Join the remaining line_split back into entry information string
        log_entry_info = ' '.join(line_split)

        #=======================
        # Determine service from log_entry_type_dirty
        #   Based on that, further parse information from the line
        #=======================
        #------------------------
        # Event Type : sudo
        #------------------------
        if log_entry == "SUDO":

            # Isolate username
            username = log_entry_info.split(':')[0].strip()
            privilege_level = "Elevated [sudo]"

            # Sudo check : apt install
            if 'apt install' in log_entry_info:
                if "netcat" in log_entry_info:
                    log_type = "COMMAND_EXECUTION"
                    log_class = "SUSPICIOUS_COMMAND"
                    log_subclass = "NETCAT_INSTALLATION"
                elif "nmap" in log_entry_info:
                    log_type = "COMMAND_EXECUTION"
                    log_class = "SUSPICIOUS_COMMAND"
                    log_subclass = "NMAP_INSTALLATION"

            # Sudo check : curl
            elif 'curl' in log_entry_info:
                log_type = "COMMAND_EXECUTION"
                log_class = "SUSPICIOUS_COMMAND"
                log_subclass = "CURL_DOWNLOAD"

                # Determine the source ip (regex is not enforcing IP address limits / allowable values)
                log_curl_ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', log_entry_info)[0]

                # Put the event together
                return LogEvent(
                    entry_timestamp=log_timestamp,
                    entry_hostname=log_hostname,
                    entry_type=log_type,
                    entry_class=log_class,
                    entry_subclass=log_subclass,
                    entry_source_ip=log_curl_ip,
                    entry_username=username,
                    entry_privilege_level=privilege_level,
                    entry_raw_log=line
                )

            # Sudo check : curl
            elif 'wget' in log_entry_info:
                log_type = "COMMAND_EXECUTION"
                log_class = "SUSPICIOUS_COMMAND"
                log_subclass = "WGET_DOWNLOAD"

                # Determine the source ip (regex is not enforcing IP address limits / allowable values)
                log_wget_ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', log_entry_info)[0]

                # Put the event together
                return LogEvent(
                    entry_timestamp=log_timestamp,
                    entry_hostname=log_hostname,
                    entry_type=log_type,
                    entry_class=log_class,
                    entry_subclass=log_subclass,
                    entry_source_ip=log_wget_ip,
                    entry_username=username,
                    entry_privilege_level=privilege_level,
                    entry_raw_log=line
                )

            # Sudo check : usermod
            elif 'usermod' in log_entry_info:
                if "-aG sudo" in log_entry_info:
                    log_type = "COMMAND_EXECUTION"
                    log_class = "PRIVILEGE_ESCALATION"
                    log_subclass = "USER_ADDED_TO_SUDO"
                elif "-aG wheel":
                    log_type = "COMMAND_EXECUTION"
                    log_class = "PRIVILEGE_ESCALATION"
                    log_subclass = "USER_ADDED_TO_WHEEL"

            # Sudo check : scp
            elif 'scp' in log_entry_info:
                log_type = "COMMAND_EXECUTION"
                log_class = "SUSPICIOUS_COMMAND"
                log_subclass = "SCP_FILE_TRANSFER"

            # Sudo check : sensitive file - shadow
            elif '/etc/shadow' in log_entry_info:
                log_type = "COMMAND_EXECUTION"
                log_class = "CREDENTIAL_ACCESS"
                log_subclass = "SHADOW_FILE_ACCESS"

            # Sudo check : sensitive file - passwd
            elif '/etc/passwd' in log_entry_info:
                log_type = "COMMAND_EXECUTION"
                log_class = "CREDENTIAL_ACCESS"
                log_subclass = "PASSWD_FILE_ACCESS"

            # Sudo check : possible exfiltration
            elif 'tar -c' in log_entry_info:
                log_type = "COMMAND_EXECUTION"
                log_class = "SUSPICIOUS_COMMAND"
                log_subclass = "TAR_ARCHIVE_CREATION"

            # Put the event together
            return LogEvent(
                entry_timestamp=log_timestamp,
                entry_hostname=log_hostname,
                entry_type=log_type,
                entry_class=log_class,
                entry_subclass=log_subclass,
                entry_username=username,
                entry_privilege_level=privilege_level,
                entry_raw_log=line
            )

        #------------------------
        # Event Type : sshd
        #------------------------
        elif log_entry == "SSHD":
            #----
            # Handle common variables
            #----
            log_type = "AUTHENTICATION"
            log_class = "AUTHENTICATION"
            # Determine the source ip (regex is not enforcing IP address limits / allowable values)
            log_source_ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',log_entry_info)[0]

            # Determine the username - extract the information via ... for <user> from ...
            log_user_name = re.search(r"for (.+) from", log_entry_info).group(1)
            # Determine the entry type
            if "Failed password" in log_entry_info:
                log_subclass = "FAILED_LOGIN"
            elif "Accepted password" in log_entry_info:
                log_subclass = "SUCCESSFUL_LOGIN"
            elif "invalid user" in log_entry_info:
                log_subclass = "INVALID_USER_LOGIN"


            # Put the event together
            return LogEvent(
                entry_timestamp=log_timestamp,
                entry_hostname=log_hostname,
                entry_type=log_type,
                entry_class=log_class,
                entry_subclass=log_subclass,
                entry_source_ip=log_source_ip,
                entry_privilege_level="Non-Elevated",
                entry_username=log_user_name,
                entry_raw_log=line
            )

        #------------------------
        # Event Type : userdel
        #------------------------
        elif log_entry == "USERDEL":
            # Event variables
            log_type = "ACCOUNT_CHANGE"
            log_class = "USER_MANAGEMENT"
            log_subclass = "USER_DELETED"

            # Isolate user deleted
            log_username = re.findall(r"'([^']*)'", log_entry_info)[0]

            # Put the event together
            return LogEvent(
                entry_timestamp=log_timestamp,
                entry_hostname=log_hostname,
                entry_type=log_type,
                entry_class=log_class,
                entry_subclass=log_subclass,
                entry_username=log_username,
                entry_privilege_level="Non-Elevated",
                entry_raw_log=line
            )

        #------------------------
        # Event Type : useradd
        #------------------------
        elif log_entry == "USERADD":
            # Determine the 'type' - mainly checking for new user currently
            if "new user:" in log_entry_info:
                log_type = "ACCOUNT_CHANGE"
                log_class = "USER_MANAGEMENT"
                log_subclass = "USER_CREATED"

                # Isolate new user log info
                new_user_info = log_entry_info.split(':')[1].replace("new user", "").strip()

                # Split again to isolate username
                username = new_user_info.split(',')[0].replace("name=", "")

                # Put the event together
                return LogEvent(
                    entry_timestamp=log_timestamp,
                    entry_hostname=log_hostname,
                    entry_type=log_type,
                    entry_class=log_class,
                    entry_subclass=log_subclass,
                    entry_username=username,
                    entry_privilege_level="Non-Elevated",
                    entry_raw_log=line
                )

        #------------------------
        # Event Type : passwd
        #------------------------
        elif log_entry == "PASSWD":
            # Ensure event is password change
            if "password changed for" in log_entry_info:
                log_type = "ACCOUNT_CHANGE"
                log_class = "USER_MANAGEMENT"
                log_subclass = "PASSWORD_CHANGED"

                # Associated user for event
                username = log_entry_info.replace("password changed for ", "").strip()

                # Put the event together
                return LogEvent(
                    entry_timestamp=log_timestamp,
                    entry_hostname=log_hostname,
                    entry_type=log_type,
                    entry_class=log_class,
                    entry_subclass=log_subclass,
                    entry_username=username,
                    entry_privilege_level="Non-Elevated",
                    entry_raw_log=line
                )

        #------------------------
        # Event Type : systemd
        #------------------------
        elif log_entry == "SYSTEMD":

            # Determine if service started / stopped / restarted
            if "Started" in log_entry_info:
                if 'telnet' in log_entry_info:
                    log_type = "SERVICE_CHANGE"
                    log_class = "DEFENSE_EVASION"
                    log_subclass = "TELNET_ENABLED"
            elif "Restarted" in log_entry_info:
                pass
            elif "Stopped" in log_entry_info:
                if 'auditd' in log_entry_info:
                    log_type = "SERVICE_CHANGE"
                    log_class = "DEFENSE_EVASION"
                    log_subclass = "AUDITD_STOPPED"
                elif 'firewalld' in log_entry_info:
                    log_type = "SERVICE_CHANGE"
                    log_class = "DEFENSE_EVASION"
                    log_subclass = "FIREWALL_STOPPED"

            # Put the event together
            return LogEvent(
                entry_timestamp=log_timestamp,
                entry_hostname=log_hostname,
                entry_type=log_type,
                entry_class=log_class,
                entry_subclass=log_subclass,
                entry_privilege_level="Non-Elevated",
                entry_raw_log=line
            )

        # Event is unknown / unparsed
        else:
            return LogEvent(
                entry_timestamp=log_timestamp,
                entry_hostname=log_hostname,
                entry_type = "UNKNOWN",
                entry_class = "UNKNOWN",
                entry_subclass="IGNORED_EVENT",
                entry_privilege_level="Non-Elevated",
                entry_raw_log=line
            )