#==========================================================================
#
#           File : CredentialAccessEvents.py
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
class ShadowFileAccessEvent(Detector):
    def processEvent(self, event, context):
        pass

#=====================================
# Detector Class : PasswdFileAccessEvent
#=====================================
class PasswdFileAccessEvent(Detector):
    def processEvent(self, event, context):
        pass
