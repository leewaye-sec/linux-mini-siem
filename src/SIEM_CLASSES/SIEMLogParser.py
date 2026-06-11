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
        log_entry_type_dirty = line_split[0]
        del line_split[0]

        # Join the remaining line_split back into entry information string
        log_entry_info = ' '.join(line_split)

        #=======================
        # Determine service from log_entry_type_dirty
        #   Based on that, further parse information from the line
        #=======================
        # Event Type : sudo
        if "sudo" in log_entry_type_dirty:
            log_entry_type = "sudo"
        # Event Type : sshd
        if "sshd" in log_entry_type_dirty:
            log_entry_type = "sshd"
        # Event Type : useradd
        if "useradd" in log_entry_type_dirty:
            log_entry_type = "useradd"
        # Event Type : passwd
        if "passwd" in log_entry_type_dirty:
            log_entry_type = "passwd"
        # Event Type : systemd
        if "systemd" in log_entry_type_dirty:
            log_entry_type = "systemd"
