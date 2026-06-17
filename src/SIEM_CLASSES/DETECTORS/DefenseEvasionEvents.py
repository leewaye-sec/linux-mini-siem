#==========================================================================
#
#           File : DefenseEvasionEvents.py
#        Project : Mini-SIEM
#    Description : Class definitions for defense evasion related events
#
#==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import LogEvent
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from src.SIEM_CLASSES.DETECTORS.DetectorBaseDefinition import Detector

#=====================================
# Detector Class : AuditdStoppedEvent
#=====================================
class AuditdStoppedEvent(Detector):
    def processEvent(self, event, context):
        pass

#=====================================
# Detector Class : FirewalldStoppedEvent
#=====================================
class FirewalldStoppedEvent(Detector):
    def processEvent(self, event, context):
        pass

#=====================================
# Detector Class : TelnetEnabledEvent
#=====================================
class TelnetEnabledEvent(Detector):
    def processEvent(self, event, context):
        pass
