# ==========================================================================
#
#           File : PrivilegeEscalationEvents.py
#        Project : Mini-SIEM
#    Description : Class definitions for privilege escalation related events
#
# ==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import LogEvent
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from src.SIEM_CLASSES.DETECTORS.DetectorBaseDefinition import Detector

#=====================================
# Detector Class : SudoActivityEvent
#=====================================
class SudoActivityEvent(Detector):
    def processEvent(self, event, context):
        pass

#==============================
# Detector Class : SudoActivityEvent
#=====================================
class SensitiveCommandEvent(Detector):
    def processEvent(self, event, context):
        pass