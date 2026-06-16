#!/usr/local/bin/python3
#==========================================================================
#
#           File : StandardizedDataStructures.py
#        Project : Mini-SIEM
#    Description : Holds the data class structures for several SIEM components
#                  Use for normalization of ingested data
#
#==========================================================================
from dataclasses import dataclass
from datetime import datetime

#------------------------
# Data Class Definition : LogEvent
#   Use : Standardize and normalize log entries
#------------------------
@dataclass
class LogEvent:
    entry_timestamp: datetime
    entry_hostname: str
    entry_class: str
    entry_class_type: str
    entry_source_ip: str | None = None
    entry_username: str | None = None
    entry_raw_log: str | None = None

#------------------------
# Data Class Definition : EventFinding
#   Use : Standardize findings when analyzing events for later reporting
#------------------------
@dataclass
class EventFinding:
    severity_level: str
    detected_finding: str
    finding_description: str
    timestamp: datetime
    source_ip: str | None = None
    associated_username: str | None = None
    event_count: int | None = None
