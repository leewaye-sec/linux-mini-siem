#==========================================================================
#
#           File : SuspiciousCommandEvents.py
#        Project : Mini-SIEM
#    Description : Class definitions for suspicious command related events
#
#==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import LogEvent
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from src.SIEM_CLASSES.DETECTORS.DetectorBaseDefinition import Detector

#=====================================
# Detector Class : NetcatInstallationEvent
#=====================================
class NetcatInstallationEvent(Detector):
    def processEvent(self, event, context):
        pass

#=====================================
# Detector Class : NmapInstallationEvent
#=====================================
class NmapInstallationEvent(Detector):
    def processEvent(self, event, context):
        pass

#=====================================
# Detector Class : CurlDownloadEvent
#=====================================
class CurlDownloadEvent(Detector):
    def processEvent(self, event, context):
        pass

#=====================================
# Detector Class : WgetDownloadEvent
#=====================================
class WgetDownloadEvent(Detector):
    def processEvent(self, event, context):
        pass
