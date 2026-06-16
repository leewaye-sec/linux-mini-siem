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

        # Log Entry Class
        #   Remove the unnecessary extra from the entry (e.g. sshd[7394]: --> sshd)
        log_class= re.sub(r"(\[\d+\]):", "", line_split[0]).upper()
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
        if log_class == "SUDO":

            # Isolate username
            username = log_entry_info.split(':')[0].strip()

            # Sudo check : apt install
            if 'apt install' in log_entry_info:
                log_class_type = "PACKAGE_INSTALLED"

            # Sudo check : useradd
            elif 'useradd' in log_entry_info:
                log_class_type = "USERADD"

            # Sudo check : curl
            elif 'curl' in log_entry_info:
                log_class_type = "CURL"

                # Determine the source ip (regex is not enforcing IP address limits / allowable values)
                log_curl_ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', log_entry_info)[0]

                # Put the event together
                return LogEvent(
                    entry_timestamp=log_timestamp,
                    entry_hostname=log_hostname,
                    entry_class=log_class,
                    entry_class_type=log_class_type,
                    entry_source_ip=log_curl_ip,
                    entry_username=username,
                    entry_raw_log=line
                )

            # Sudo check : usermod
            elif 'usermod' in log_entry_info:
                log_class_type = "USERMOD"

            # Sudo check : scp
            elif 'scp' in log_entry_info:
                log_class_type = "SCP"

            # Sudo check : sensitive file
            elif 'cat /etc/shadow' in log_entry_info:
                log_class_type = "CAT_SHADOW"

            # Sudo check : possible exfiltration
            elif 'tar ' in log_entry_info:
                log_class_type = "TARBALL_CREATED"

            else:
                log_class_type = "SUDO"

            # Put the event together
            return LogEvent(
                entry_timestamp=log_timestamp,
                entry_hostname=log_hostname,
                entry_class=log_class,
                entry_class_type=log_class_type,
                entry_username=username,
                entry_raw_log=line
            )

        #------------------------
        # Event Type : sshd
        #------------------------
        elif log_class == "SSHD":
            # Determine the entry type
            if "Failed password" in log_entry_info:
                log_class_type = "FAILED_LOGIN_ATTEMPT"
            elif "Accepted password" in log_entry_info:
                log_class_type = "SUCCESSFUL_LOGIN_ATTEMPT"
            elif "invalid user" in log_entry_info:
                log_class_type = "INVALID_USERNAME"
            else:
                log_class_type = "SSHD"

            # Determine the source ip (regex is not enforcing IP address limits / allowable values)
            log_source_ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',log_entry_info)[0]

            # Determine the username - extract the information via ... for <user> from ...
            log_user_name = re.search(r"for (.+) from", log_entry_info).group(1)

            # Put the event together
            return LogEvent(
                entry_timestamp=log_timestamp,
                entry_hostname=log_hostname,
                entry_class=log_class,
                entry_class_type=log_class_type,
                entry_source_ip=log_source_ip,
                entry_username=log_user_name,
                entry_raw_log=line
            )

        #------------------------
        # Event Type : useradd
        #------------------------
        elif log_class == "USERADD":
            # Determine the 'type' - mainly checking for new user currently
            if "new user:" in log_entry_info:
                log_class_type = "NEW_USER"

                # Isolate new user log info
                new_user_info = log_entry_info.split(':')[1].replace("new user", "").strip()

                # Split again to isolate username
                username = new_user_info.split(',')[0].replace("name=", "")

                # Put the event together
                return LogEvent(
                    entry_timestamp=log_timestamp,
                    entry_hostname=log_hostname,
                    entry_class=log_class,
                    entry_class_type=log_class_type,
                    entry_username=username,
                    entry_raw_log=line
                )

        #------------------------
        # Event Type : passwd
        #------------------------
        elif log_class == "PASSWD":
            # Ensure event is password change
            if "password changed for" in log_entry_info:
                log_class_type = "PASSWD_CHANGED"

                # Associated user for event
                username = log_entry_info.replace("password changed for ", "").strip()

                # Put the event together
                return LogEvent(
                    entry_timestamp=log_timestamp,
                    entry_hostname=log_hostname,
                    entry_class=log_class,
                    entry_class_type=log_class_type,
                    entry_username=username,
                    entry_raw_log=line
                )

        #------------------------
        # Event Type : systemd
        #------------------------
        elif log_class == "SYSTEMD":

            # Determine if service started / stopped / restarted
            log_class_type = "SYSTEMD"
            if "Started" in log_entry_info:
                log_class_type = "SERVICE_STARTED"
            elif "Restarted" in log_entry_info:
                log_class_type = "SERVICE_RESTARTED"
            elif "Stopped" in log_entry_info:
                log_class_type = "SERVICE_STOPPED"

            # Put the event together
            return LogEvent(
                entry_timestamp=log_timestamp,
                entry_hostname=log_hostname,
                entry_class=log_class,
                entry_class_type=log_class_type,
                entry_raw_log=line
            )

        # Event is unknown / unparsed
        else:
            return None