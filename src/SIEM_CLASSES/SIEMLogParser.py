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
        # Event Type : sudo
        if log_class == "SUDO":
            log_class_type = "sudo"
        # Event Type : sshd
        if log_class == "SSHD":
            # Determine the entry type
            if "Failed password" in log_entry_info:
                log_class_type = "FAILED_LOGIN_ATTEMPT"
            elif "Accepted password" in log_entry_info:
                log_class_type = "SUCCESSFUL_LOGIN_ATTEMPT"

            # Determine the source ip (regex is not enforcing IP address limits / allowable values)
            log_source_ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',log_entry_info)[0]

            # Determine the username - extract the information via ... for <user> from ...
            log_user_name = re.search(r"for (.+) from", log_entry_info).group(1)

            # Put the event together
            LogEvent(
                entry_timestamp=log_timestamp,
                entry_hostname=log_hostname,
                entry_class=log_class,
                entry_class_type=log_class_type,
                entry_source_ip=log_source_ip,
                entry_username=log_user_name,
                entry_raw_log=line
            )
            return LogEvent

        # Event Type : useradd
        if log_class == "USERADD":
            log_class_type = "useradd"
        # Event Type : passwd
        if log_class == "PASSWD":
            log_class_type = "passwd"
        # Event Type : systemd
        if log_class == "SYSTEMD":
            log_class_type = "systemd"
