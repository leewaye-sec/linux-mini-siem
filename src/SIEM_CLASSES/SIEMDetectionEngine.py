#!/usr/local/bin/python3
#==========================================================================
#
#           File : SIEMDetectionEngine.py
#        Project : Mini-SIEM
#    Description : Class definition for event detection and correlation
#
#==========================================================================
#----------------
# Imports
#----------------
import re
from datetime import datetime

# Import the Detector Classes
from SIEMDetectorDefinitions import SSHBruteForceDetector
from SIEMDetectorDefinitions import UserCreationDetector
from SIEMDetectorDefinitions import SudoActivityDetector
from SIEMDetectorDefinitions import SuccessfulLoginDetector

#===============================
# Class Definition
#===============================
class SIEMDetectionEngine:
    def __init__(self):
        self.eventDetectors = [
            SSHBruteForceDetector(),
            UserCreationDetector(),
            SudoActivityDetector(),
            SuccessfulLoginDetector()
        ]
