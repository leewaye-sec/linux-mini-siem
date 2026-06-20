#==========================================================================
#
#           File : CredentialAccessDetector.py
#        Project : Mini-SIEM
#    Description : Class definitions for credential access related events
#
#==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import LogEvent
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from src.SIEM_CLASSES.DETECTORS.DetectorBaseDefinition import Detector

#=====================================
# Detector Class : ShadowFileAccessEvent
#=====================================
class ShadowFileAccessDetector(Detector):
    def processEvent(self, event, context):
        # Process if event marked for /etc/shadow access
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "CREDENTIAL_ACCESS" and event.entry_subclass == "SHADOW_FILE_ACCESS":
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Access of sensitive file [ /etc/shadow ]",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    privilege_level=event.entry_privilege_level
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : PasswdFileAccessEvent
#=====================================
class PasswdFileAccessDetector(Detector):
    def processEvent(self, event, context):
        # Process if event marked for /etc/passwd access
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "CREDENTIAL_ACCESS" and event.entry_subclass == "PASSWD_FILE_ACCESS":
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Access of sensitive file [ /etc/passwd ]",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    privilege_level=event.entry_privilege_level
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []
