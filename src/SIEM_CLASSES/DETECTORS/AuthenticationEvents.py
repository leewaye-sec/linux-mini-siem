#==========================================================================
#
#           File : AuthenticationEvents.py
#        Project : Mini-SIEM
#    Description : Class definitions for authentication related events
#
#==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import LogEvent
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from src.SIEM_CLASSES.DETECTORS.DetectorBaseDefinition import Detector

#=====================================
# Detector Class : SSHBruteForceDetector
#=====================================
class SSHBruteForceDetector(Detector):

    def processEvent(self, event, context):
        # Define the decision pathways
        if event.entry_class == "SSHD" and event.entry_class_type == "FAILED_LOGIN_ATTEMPT":

            #--------------
            # Begin processing for failed logins
            #--------------
            # Retrieve IP assoc. with event
            failure_ip = event.entry_source_ip

            # Associated username
            event_username = event.entry_username

            # Retrieve number of failed logins associated with the IP
            #   Use .get() to ensure value is returned (if nothing exists, give 0)
            #   Update number of failed logins
            context.failed_logins[failure_ip] = (context.failed_logins.get(failure_ip, 0) + 1)

            #--------------
            # Determine finding levels
            #   Not reporting username in finding to focus on source
            #--------------
            # Single Login Failure -- LOW -- Within normal user behavior
            if context.failed_logins[failure_ip] == 1:
                if event.entry_username == "root":
                    return [
                        EventFinding(
                            severity_level="HIGH",
                            detected_finding=event.entry_class_type,
                            finding_description="Failed Login Attempt for root",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            associated_username=event_username,
                            event_count=context.failed_logins.get(failure_ip)
                        )
                    ]
                else:
                    return [
                        EventFinding(
                            severity_level="INFO",
                            detected_finding=event.entry_class_type,
                            finding_description="Single Failed Login Attempt",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            associated_username=event_username,
                            event_count=context.failed_logins.get(failure_ip)
                        )
                    ]

            # Mutliple Login Failures Under Threshold -- MEDIUM -- Potential exists for brute force
            elif context.failed_logins[failure_ip] >= context.getFailedLoginsThreshold():
                if event.entry_username == "root":
                    return [
                        EventFinding(
                            severity_level="HIGH",
                            detected_finding=event.entry_class_type,
                            finding_description="Multiple Failed Login Attempts for root",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            associated_username=event_username,
                            event_count=context.failed_logins.get(failure_ip)
                        )
                    ]
                else:
                    return[
                        EventFinding(
                            severity_level="MEDIUM",
                            detected_finding=event.entry_class_type,
                            finding_description="Multiple Failed Login Attempts",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            associated_username=event_username,
                            event_count=context.failed_logins.get(failure_ip)
                        )
                    ]

            # Mutliple Login Failures At or Above Threshold -- CRITICAL -- Likely active brute force
            elif context.failed_logins[failure_ip] >= context.getFailedLoginsThreshold():
                if event.entry_username == "root":
                    return [
                        EventFinding(
                            severity_level="HIGH",
                            detected_finding=event.entry_class_type,
                            finding_description="Multiple Failed Login Attempts for root",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            associated_username=event_username,
                            event_count=context.failed_logins.get(failure_ip)
                        )
                    ]
                else:
                    return [
                        EventFinding(
                            severity_level="HIGH",
                            detected_finding="SSH_BRUTE_FORCE",
                            finding_description=f"[ {context.failed_logins.get(failure_ip)} ] Failed Logins Detected",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            associated_username=event_username,
                            event_count=context.failed_logins.get(failure_ip)
                        )
                    ]
        else:
            return []

#=====================================
# Detector Class : SuccessfulLoginEvent
#=====================================
class SuccessfulLoginEvent(Detector):
    def processEvent(self, event, context):

        # Retrieve ip addr
        successful_login_ip = event.entry_source_ip

        #Retrieve username
        login_username = event.entry_username

        login_attempts = context.failed_logins.get(successful_login_ip, 0)
        login_threshold = context.getFailedLoginsThreshold()

        # Define the decision pathways
        # Handle multiple possible correlated events
        if event.entry_class == "SSHD" and event.entry_class_type == "SUCCESSFUL_LOGIN_ATTEMPT":
            # Process for non-root users
            if event.entry_username != "root":
                # Single Success with no Failures
                if login_attempts == 0:
                    return [
                        EventFinding(
                            severity_level="INFO",
                            detected_finding=f"{event.entry_class_type}",
                            finding_description=f"Successful login detected with [ {login_attempts} ] failures",
                            timestamp=event.entry_timestamp,
                            source_ip=successful_login_ip,
                            associated_username=login_username
                        )
                    ]
                # Single Success with some Failures
                elif login_attempts < login_threshold:
                    return [
                        EventFinding(
                            severity_level="LOW",
                            detected_finding=f"{event.entry_class_type}",
                            finding_description=f"Successful login detected with [ {login_attempts} ] failures",
                            timestamp=event.entry_timestamp,
                            source_ip=successful_login_ip,
                            associated_username=login_username,
                            event_count=context.failed_logins.get(successful_login_ip)
                        )
                    ]
                #   Single Success with many Failures
                elif login_attempts >= login_threshold:
                    return [
                        EventFinding(
                            severity_level="CRITICAL",
                            detected_finding=f"{event.entry_class_type}",
                            finding_description=f"Successful login detected with [ {login_attempts} ] failures",
                            timestamp=event.entry_timestamp,
                            source_ip=successful_login_ip,
                            associated_username=login_username,
                            event_count=context.failed_logins.get(successful_login_ip)
                        )
                    ]
            else:
                return []
        else:
            return []

#=====================================
# Detector Class : InvalidUserAuthenticationEvent
#=====================================
class InvalidUserAuthenticationEvent(Detector):
    def processEvent(self, event, context):

        # Retrieve some variables
        login_ip = event.entry_source_ip
        login_username = event.entry_username

        if event.entry_class == "SSHD" and event.entry_class_type == "INVALID_USERNAME":
            return [
                EventFinding(
                    severity_level="LOW",
                    detected_finding=f"{event.entry_class_type}",
                    finding_description=f"Attempted Login with Invalid User {context.failed_logins.get()}",
                    timestamp=event.entry_timestamp,
                    source_ip=login_ip,
                    associated_username=login_username,
                    event_count=context.failed_logins.get(login_ip)
                )
            ]

#=====================================
# Detector Class : RootLoginEvent
#=====================================
class RootLoginEvent(Detector):
    def processEvent(self, event, context):
        # Retrieve ip addr
        successful_login_ip = event.entry_source_ip

        #Retrieve username
        login_username = event.entry_username

        login_attempts = context.failed_logins.get(successful_login_ip, 0)

        if event.entry_class == "SSHD" and event.entry_class_type == "SUCCESSFUL_LOGIN_ATTEMPT" and login_username == "root":
            return [
                EventFinding(
                    severity_level="CRITICAL",
                    detected_finding=f"{event.entry_class_type}",
                    finding_description=f"Root Login Success after [ {login_attempts} ] Failures",
                    timestamp=event.entry_timestamp,
                    source_ip=successful_login_ip,
                    associated_username=login_username,
                    event_count=context.failed_logins.get(successful_login_ip)
                )
    ]
