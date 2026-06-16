#==========================================================================
#
#           File : ServiceModificationEvents.py
#        Project : Mini-SIEM
#    Description : Class definitions for service modification related events
#
#==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import LogEvent
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from src.SIEM_CLASSES.DETECTORS.DetectorBaseDefinition import Detector

#=====================================
# Detector Class : ServiceStopEvent
#=====================================
class ServiceStopEvent(Detector):
    def processEvent(self, event, context):
        pass

#==============================
# Detector Class : SecurityControlDisabledEvent
#=====================================
class SecurityControlDisabledEvent(Detector):
    def processEvent(self, event, context):
        pass

#==============================
# Detector Class : LegacyServiceEnabledEvent
#=====================================
class LegacyServiceEnabledEvent(Detector):
    def processEvent(self, event, context):
        pass
