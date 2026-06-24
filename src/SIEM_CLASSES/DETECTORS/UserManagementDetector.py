# ==========================================================================
#
#           File : UserManagementDetector.py
#        Project : Mini-SIEM
#    Description : Class definitions for user management related events
#
# ==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from .DetectorBaseDefinition import BaseDetector

#=====================================
# Detector Class : UserCreationEvent
#=====================================
class UserCreationDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "ACCOUNT_CHANGE" and event.entry_class == "USER_MANAGEMENT" and event.entry_subclass == "USER_CREATED":
            return [
                EventFinding(
                    severity_level="MEDIUM",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"User management [ New User ]",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    associated_hostname=event.entry_hostname,
                    privilege_level=event.entry_privilege_level
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#==============================
# Detector Class : UserDeletionEvent
#=====================================
class UserDeletionDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "ACCOUNT_CHANGE" and event.entry_class == "USER_MANAGEMENT" and event.entry_subclass == "USER_DELETED":
            return [
                EventFinding(
                    severity_level="MEDIUM",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"User management [ User Deleted ]",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    associated_hostname=event.entry_hostname,
                    privilege_level=event.entry_privilege_level
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#==============================
# Detector Class : PasswordChangeEvent
#=====================================
class PasswordChangeDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "ACCOUNT_CHANGE" and event.entry_class == "USER_MANAGEMENT" and event.entry_subclass == "PASSWORD_CHANGED":
            return [
                EventFinding(
                    severity_level="MEDIUM",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"User management [ User Password Change ]",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    associated_hostname=event.entry_hostname,
                    privilege_level=event.entry_privilege_level,
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []
