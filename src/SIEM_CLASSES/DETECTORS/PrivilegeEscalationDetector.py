# ==========================================================================
#
#           File : PrivilegeEscalationDetector.py
#        Project : Mini-SIEM
#    Description : Class definitions for privilege escalation related events
#
# ==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from .DetectorBaseDefinition import BaseDetector

#==============================
# Detector Class : UserAddedToSudoEvent
#=====================================
class UserAddedToSudoDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "PRIVILEGE_ESCALATION" and event.entry_subclass == "USER_ADDED_TO_SUDO":
            # Grab the information for what user was added to sudo
            log = event.entry_raw_log
            # Isolate command
            command = log.split(':')[-1].split(';')[-1]
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"User added to privileged group [ sudo ]",
                    timestamp=event.entry_timestamp,
                    associated_username= event.entry_username,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : UserAddedToWheelEvent
#=====================================
class UserAddedToWheelDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "PRIVILEGE_ESCALATION" and event.entry_subclass == "USER_ADDED_TO_WHEEL":
            # Grab the information for what user was added to sudo
            log = event.entry_raw_log
            # Isolate command
            command = log.split(':')[-1].split(';')[-1]
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"User added to privileged group [ wheel ]",
                    timestamp=event.entry_timestamp,
                    associated_username= event.entry_username,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []
