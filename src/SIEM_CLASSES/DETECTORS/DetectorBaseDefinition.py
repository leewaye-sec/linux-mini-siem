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

#=====================================
# Base Class : Detector
#=====================================
class BaseDetector(ABC):
    @abstractmethod
    def processEvent(self, event, context):
            pass
