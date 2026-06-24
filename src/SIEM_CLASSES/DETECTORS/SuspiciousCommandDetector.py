#==========================================================================
#
#           File : SuspiciousCommandDetector.py
#        Project : Mini-SIEM
#    Description : Class definitions for suspicious command related events
#
#==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from .DetectorBaseDefinition import BaseDetector

#=====================================
# Detector Class : NetcatInstallationEvent
#=====================================
class NetcatInstallationDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "NETCAT_INSTALLATION":
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Package installation [ netcat ]",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    associated_hostname=event.entry_hostname,
                    privilege_level=event.entry_privilege_level,
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : NmapInstallationEvent
#=====================================
class NmapInstallationDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "NMAP_INSTALLATION":
            return [
                EventFinding(
                    severity_level="MEDIUM",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Package installation [ nmap ]",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    associated_hostname=event.entry_hostname,
                    privilege_level=event.entry_privilege_level,
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : CurlDownloadEvent
#=====================================
class CurlDownloadDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "CURL_DOWNLOAD":
            # Isolate command
            log = event.entry_raw_log
            command = log.split(':')[-1].split(';')[-1]
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Curl Download Initiated",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    associated_hostname=event.entry_hostname,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : WgetDownloadEvent
#=====================================
class WgetDownloadDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "WGET_DOWNLOAD":
            # Isolate command
            log = event.entry_raw_log
            command = log.split(':')[-1].split(';')[-1]
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Wget Download Initiated",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    associated_hostname=event.entry_hostname,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : tarCreationDetector
#=====================================
class TarCreationDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "TAR_ARCHIVE_CREATION":
            # Isolate command
            log = event.entry_raw_log
            command = log.split(':')[-1].split(';')[-1]
            return [
                EventFinding(
                    severity_level="MEDIUM",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Tar Archive Created",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    associated_hostname=event.entry_hostname,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : SCPFileTransferDetector
#=====================================
class SCPFileTransferDetector(BaseDetector):
    def processEvent(self, event, context):
        if event.entry_type == "COMMAND_EXECUTION" and event.entry_class == "SUSPICIOUS_COMMAND" and event.entry_subclass == "SCP_FILE_TRANSFER":
            # Isolate command
            log = event.entry_raw_log
            command_dirty = f"{log.split(':')[-2]}:{log.split(':')[-1]}"
            command = command_dirty.split(';')[-1]
            return [
                EventFinding(
                    severity_level="HIGH",
                    detected_finding=f"{event.entry_subclass}",
                    finding_description=f"Secure file transfer initiated",
                    timestamp=event.entry_timestamp,
                    associated_username=event.entry_username,
                    associated_hostname=event.entry_hostname,
                    privilege_level=event.entry_privilege_level,
                    additional_details=command
                )
            ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []
