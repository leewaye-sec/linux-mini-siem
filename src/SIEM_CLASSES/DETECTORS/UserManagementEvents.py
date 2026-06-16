# ==========================================================================
#
#           File : UserManagementEvents.py
#        Project : Mini-SIEM
#    Description : Class definitions for user management related events
#
# ==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import LogEvent
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from src.SIEM_CLASSES.DETECTORS.DetectorBaseDefinition import Detector

#=====================================
# Detector Class : UserCreationEvent
#=====================================
class UserCreationEvent(Detector):
    def processEvent(self, event, context):
        pass

#==============================
# Detector Class : UserDeletionEvent
#=====================================
class UserDeletionEvent(Detector):
    def processEvent(self, event, context):
        pass

#==============================
# Detector Class : GroupModificationEvent
#=====================================
class GroupModificationEvent(Detector):
    def processEvent(self, event, context):
        pass
