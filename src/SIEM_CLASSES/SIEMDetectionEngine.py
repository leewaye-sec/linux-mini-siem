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
# Import the Dataclasses
from StandardizedDataStructures import LogEvent

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

        #-------------------------
        # Authentication Contexts
        #-------------------------
        # failed_logins = ip : failed_login_count
        self.failed_logins = {}
        self.failed_logins_threshold = 3
        self.invalid_username_logins = {}
        self.invalid_username_threshold = 3

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
            SSHBruteForceDetector(),
            SuccessfulLoginDetector(),
            InvalidUserAuthenticationDetector(),
            RootLoginDetector(),
            UserCreationDetector(),
            UserDeletionDetector(),
            PasswordChangeDetector(),
            UserAddedToSudoDetector(),
            UserAddedToWheelDetector(),
            ShadowFileAccessDetector(),
            PasswdFileAccessDetector(),
            AuditdStoppedDetector(),
            FirewalldStoppedDetector(),
            TelnetEnabledDetector(),
            NetcatInstallationDetector(),
            NmapInstallationDetector(),
            CurlDownloadDetector(),
            WgetDownloadDetector(),
            SCPFileTransferDetector(),
            TarCreationDetector()
        ]

        # Keep track of log stateful data
        self.eventContexts = SystemEventContext()

    # Process
    def process(self, event: LogEvent):

        # Have list to store findings
        all_findings = []

        # Work through Detectors for passed event
        #   Extend the all_findings array with finding arrays returned
        for eDetector in self.eventDetectors:
            all_findings.extend(eDetector.processEvent(event, self.eventContexts))

        return all_findings