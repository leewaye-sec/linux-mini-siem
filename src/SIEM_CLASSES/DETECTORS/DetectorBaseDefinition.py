#==========================================================================
#
#           File : DetectorBaseDefinition.py
#        Project : Mini-SIEM
#    Description : Prototype / Base Definition for detectors' class definitions
#                  Utilizes ABC to ensure Detector class is not instantiated directly
#                  Utilizes abstractmethod to ensure 'processEvent' method is implemented for all subclasses
#
#==========================================================================
from abc import ABC, abstractmethod
from src.SIEM_CLASSES.StandardizedDataStructures import LogEvent
from src.SIEM_CLASSES.SIEMDetectionEngine import SystemEventContext

#=====================================
# Base Class : Detector
#=====================================
class Detector(ABC):
    @abstractmethod
    def processEvent(self, event: LogEvent, context: SystemEventContext):
        pass
