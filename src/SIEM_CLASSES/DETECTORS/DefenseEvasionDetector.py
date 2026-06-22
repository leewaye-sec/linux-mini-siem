#==========================================================================
#
#           File : DefenseEvasionDetector.py
#        Project : Mini-SIEM
#    Description : Class definitions for defense evasion related events
#
#==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from .DetectorBaseDefinition import BaseDetector

#=====================================
# Detector Class : AuditdStoppedEvent
#=====================================
class AuditdStoppedDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "SERVICE_CHANGE" and event.entry_class == "DEFENSE_EVASION" and event.entry_subclass == "AUDITD_STOPPED":
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Service Stopped [ auditd ]",
                    timestamp=event.entry_timestamp,
                    privilege_level=event.entry_privilege_level
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : FirewalldStoppedEvent
#=====================================
class FirewalldStoppedDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "SERVICE_CHANGE" and event.entry_class == "DEFENSE_EVASION" and event.entry_subclass == "FIREWALL_STOPPED":
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Service Stopped [ firewalld ]",
                    timestamp=event.entry_timestamp,
                    privilege_level=event.entry_privilege_level
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : TelnetEnabledEvent
#=====================================
class TelnetEnabledDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "SERVICE_CHANGE" and event.entry_class == "DEFENSE_EVASION" and event.entry_subclass == "TELNET_ENABLED":
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Legacy Service Enabled [ telnet ]",
                    timestamp=event.entry_timestamp,
                    privilege_level=event.entry_privilege_level
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []
