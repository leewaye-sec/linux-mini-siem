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

# Import the Dataclasses
from StandardizedDataStructures import LogEvent
from StandardizedDataStructures import EventFinding

# Import the Detector Classes
from DETECTORS import (
    SSHBruteForceDetector,
    SuccessfulLoginDetector,
    InvalidUserAuthenticationDetector,
    RootLoginDetector,
    UserCreationDetector,
    UserDeletionDetector,
    PasswordChangeDetector,
    UserAddedToSudoDetector,
    UserAddedToWheelDetector,
    ShadowFileAccessDetector,
    PasswdFileAccessDetector,
    AuditdStoppedDetector,
    FirewalldStoppedDetector,
    TelnetEnabledDetector,
    NetcatInstallationDetector,
    NmapInstallationDetector,
    CurlDownloadDetector,
    WgetDownloadDetector,
    SCPFileTransferDetector,
    TarCreationDetector
)

#===============================
# Class Definition : SystemEventContext
#   Works to keep stateful information between detectors / detection engine
#===============================
class SystemEventContext:
    def __init__(self):

        #----------------
        # Authentication
        #----------------
        self.failed_logins = {}
        self.failed_logins_threshold = 5
        self.invalid_username_logins = {}
        self.invalid_username_threshold = 5

        self.created_users = {}

        #----------------
        # Privilege Escalation
        #----------------

    # Define a few value return functions
    def getFailedLoginsThreshold(self):
        return self.failed_logins_threshold

    def getInvalidUsernameThreshold(self):
        return self.invalid_username_threshold

#===============================
# Class Definition : DetectionEngine
#===============================
class SIEMDetectionEngine:
    def __init__(self):
        # Detectors
        self.eventDetectors = [
        ]

        # Keep track of log stateful data
        self.eventContexts = SystemEventContext()


    def process(self, event: LogEvent):

        # Have list to store findings
        all_findings = []

        # Work through Detectors for passed event
        for eDetector in self.eventDetectors:
            event_finding = eDetector.processEvent(event, self.eventContexts)

            # If event_finding returned, add returned finding to event_findings list
            if event_finding:
                all_findings.extend(event_finding)



