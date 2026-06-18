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
class NetcatInstallationDetector(Detector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "NETCAT_INSTALLATION":
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Package installation [ netcat ]",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    privilege_level=event.entry_privilege_level,
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : NmapInstallationEvent
#=====================================
class NmapInstallationDetector(Detector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "NMAP_INSTALLATION":
            return [
                EventFinding(
                    severity_level="MEDIUM",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Package installation [ nmap ]",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    privilege_level=event.entry_privilege_level,
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : CurlDownloadEvent
#=====================================
class CurlDownloadDetector(Detector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "CURL_DOWNLOAD":
            # Isolate command
            log = event.entry_raw_log
            command = log.split(':')[-1].split(';')[-1]
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : WgetDownloadEvent
#=====================================
class WgetDownloadDetector(Detector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "WGET_DOWNLOAD":
            # Isolate command
            log = event.entry_raw_log
            command = log.split(':')[-1].split(';')[-1]
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : tarCreationDetector
#=====================================
class TarCreationDetector(Detector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "TAR_ARCHIVE_CREATION":
            # Isolate command
            log = event.entry_raw_log
            command = log.split(':')[-1].split(';')[-1]
            return [
                EventFinding(
                    severity_level="MEDIUM",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : SCPFileTransferDetector
#=====================================
class SCPFileTransferDetector(Detector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "SCP_FILE_TRANSFER":
            # Isolate command
            log = event.entry_raw_log
            command = log.split(':')[-1].split(';')[-1]
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []
