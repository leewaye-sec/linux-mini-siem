#==========================================================================
#
#           File : AuthenticationDetector.py
#        Project : Mini-SIEM
#    Description : Class definitions for authentication related events
#
#==========================================================================
# Import data classes
from src.SIEM_CLASSES.StandardizedDataStructures import EventFinding

# Import base detector
from .DetectorBaseDefinition import BaseDetector

#=====================================
# Detector Class : SSHBruteForceDetector
#=====================================
class SSHBruteForceDetector(BaseDetector):

    def processEvent(self, event, context):
        # Define the decision pathways
        if event.entry_class == "AUTHENTICATION" and event.entry_subclass == "FAILED_LOGIN":

            #--------------
            # Begin processing for failed logins
            #--------------
            # Retrieve IP assoc. with event
            failure_ip = event.entry_source_ip

            # Associated username
            event_username = event.entry_username

            # Retrieve number of failed logins associated with the IP and username
            #   Use .get() to ensure value is returned (if nothing exists, give 0)
            failed_login_count = context.failed_logins.get(failure_ip, {}).get(event_username, 0)

            #   Update number of failed logins
            if failed_login_count:
                context.failed_logins[failure_ip][event_username] = failed_login_count + 1
            else:
                failed_login_count = 1
                new_failed_login = {
                    event_username: failed_login_count
                }
                context.failed_logins[failure_ip] = new_failed_login

            #--------------
            # Determine finding levels
            #   Not reporting username in finding to focus on source
            #--------------
            # Single Login Failure -- LOW -- Within normal user behavior
            if failed_login_count == 1:
                if event_username == "root":
                    return [
                        EventFinding(
                            severity_level="HIGH",
                            detected_finding=f"{event.entry_subclass}_ROOT",
                            finding_description="Failed Login Attempt for root",
                            timestamp=event.entry_timestamp,
                            privilege_level=event.entry_privilege_level,
                            source_ip=failure_ip,
                            associated_username=event_username,
                            associated_hostname=event.entry_hostname,
                            event_count=failed_login_count
                        )
                    ]
                else:
                    # May remove if logging / findings become flooded
                    return [
                        EventFinding(
                            severity_level="INFO",
                            detected_finding=event.entry_subclass,
                            finding_description="Single Failed Login Attempt",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            privilege_level=event.entry_privilege_level,
                            associated_username=event_username,
                            associated_hostname=event.entry_hostname,
                            event_count=failed_login_count
                        )
                    ]

            # Mutliple Login Failures Under Threshold -- MEDIUM -- Potential exists for brute force
            elif failed_login_count < context.getFailedLoginsThreshold():
                if event_username == "root":
                    return [
                        EventFinding(
                            severity_level="HIGH",
                            detected_finding=f"{event.entry_subclass}_ROOT",
                            finding_description="Multiple Failed Login Attempts for root",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            privilege_level=event.entry_privilege_level,
                            associated_username=event_username,
                            associated_hostname=event.entry_hostname,
                            event_count=failed_login_count
                        )
                    ]
                else:
                    return[
                        EventFinding(
                            severity_level="MEDIUM",
                            detected_finding=event.entry_subclass,
                            finding_description="Multiple Failed Login Attempts",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            privilege_level=event.entry_privilege_level,
                            associated_username=event_username,
                            associated_hostname=event.entry_hostname,
                            event_count=failed_login_count
                        )
                    ]

            # Mutliple Login Failures At or Above Threshold -- HIGH -- Likely active brute force
            elif failed_login_count >= context.getFailedLoginsThreshold():
                if event_username == "root":
                    return [
                        EventFinding(
                            severity_level="CRITICAL",
                            detected_finding=f"SSH_BRUTE_FORCE",
                            finding_description="Multiple Failed Login Attempts for root",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            privilege_level=event.entry_privilege_level,
                            associated_username=event_username,
                            associated_hostname=event.entry_hostname,
                            event_count=failed_login_count
                        )
                    ]
                else:
                    return [
                        EventFinding(
                            severity_level="HIGH",
                            detected_finding="SSH_BRUTE_FORCE",
                            finding_description=f"[ {failed_login_count} ] Failed Logins Detected",
                            timestamp=event.entry_timestamp,
                            source_ip=failure_ip,
                            privilege_level=event.entry_privilege_level,
                            associated_username=event_username,
                            associated_hostname=event.entry_hostname,
                            event_count=failed_login_count
                        )
                    ]
        return []

#=====================================
# Detector Class : SuccessfulLoginEvent
#=====================================
class SuccessfulLoginDetector(BaseDetector):
    def processEvent(self, event, context):

        # Define the decision pathways
        # Handle multiple possible correlated events
        if event.entry_class == "AUTHENTICATION" and event.entry_subclass == "SUCCESSFUL_LOGIN" and event.entry_username != "root":

            # Retrieve ip addr
            successful_login_ip = event.entry_source_ip

            #Retrieve username
            login_username = event.entry_username

            login_attempts = context.failed_logins.get(successful_login_ip, 0)
            login_threshold = context.getFailedLoginsThreshold()

            # Process for non-root users
            if event.entry_username != "root":
                # Single Success with no Failures
                if login_attempts == 0:
                    return [
                        EventFinding(
                            severity_level="INFO",
                            detected_finding=f"{event.entry_subclass}",
                            finding_description=f"Successful login detected with [ {login_attempts} ] failures",
                            timestamp=event.entry_timestamp,
                            source_ip=successful_login_ip,
                            privilege_level=event.entry_privilege_level,
                            associated_hostname=event.entry_hostname,
                            associated_username=login_username
                        )
                    ]
                # Single Success with some Failures
                elif login_attempts < login_threshold:
                    return [
                        EventFinding(
                            severity_level="LOW",
                            detected_finding=f"{event.entry_subclass}",
                            finding_description=f"Successful login detected with [ {login_attempts} ] failures",
                            timestamp=event.entry_timestamp,
                            source_ip=successful_login_ip,
                            privilege_level=event.entry_privilege_level,
                            associated_username=login_username,
                            associated_hostname=event.entry_hostname,
                            event_count=context.failed_logins.get(successful_login_ip)
                        )
                    ]
                #   Single Success with many Failures
                elif login_attempts >= login_threshold:
                    return [
                        EventFinding(
                            severity_level="CRITICAL",
                            detected_finding=f"{event.entry_subclass}",
                            finding_description=f"Successful login detected with [ {login_attempts} ] failures",
                            timestamp=event.entry_timestamp,
                            source_ip=successful_login_ip,
                            privilege_level=event.entry_privilege_level,
                            associated_username=login_username,
                            associated_hostname=event.entry_hostname,
                            event_count=context.failed_logins.get(successful_login_ip)
                        )
                    ]
            # Root Login Checked via different detector
            else:
                return []
        return []

#=====================================
# Detector Class : InvalidUserAuthenticationEvent
#=====================================
class InvalidUserAuthenticationDetector(BaseDetector):
    def processEvent(self, event, context):

        if event.entry_class == "AUTHENTICATION" and event.entry_subclass == "INVALID_USER_LOGIN":

            #--------------
            # Begin processing for failed logins with invalid user
            #--------------
            # Retrieve IP assoc. with event
            login_ip = event.entry_source_ip

            # Associated username
            login_username = event.entry_username

            # Retrieve number of failed logins associated with the IP and username
            #   Use .get() to ensure value is returned (if nothing exists, give 0)

            #invalid_username_logins
            invalid_login_count = context.invalid_username_logins.get(login_ip, {}).get(login_username, 0)

            #   Update number of failed logins
            if invalid_login_count:
                context.invalid_username_logins[login_ip][login_username] = invalid_login_count + 1
            else:
                invalid_login_count = 1
                new_invalid_login = {
                    login_username: invalid_login_count
                }
                context.invalid_username_logins[login_ip] = new_invalid_login

            if invalid_login_count == 1:
                return [
                    EventFinding(
                        severity_level="LOW",
                        detected_finding=f"{event.entry_subclass}",
                        finding_description=f"Attempted Login with Invalid User [ Attempt : {invalid_login_count} ]",
                        timestamp=event.entry_timestamp,
                        source_ip=login_ip,
                        privilege_level=event.entry_privilege_level,
                        associated_username=login_username,
                        associated_hostname=event.entry_hostname,
                        event_count=invalid_login_count
                    )
                ]
            elif invalid_login_count < context.getInvalidUsernameThreshold():
                return [
                    EventFinding(
                        severity_level="MEDIUM",
                        detected_finding=f"{event.entry_subclass}",
                        finding_description=f"Multiple attempted Login with Invalid User [ Attempt : {invalid_login_count} ]",
                        timestamp=event.entry_timestamp,
                        source_ip=login_ip,
                        privilege_level=event.entry_privilege_level,
                        associated_username=login_username,
                        associated_hostname=event.entry_hostname,
                        event_count=invalid_login_count
                    )
                ]
            elif invalid_login_count >= context.getInvalidUsernameThreshold():
                return [
                    EventFinding(
                        severity_level="HIGH",
                        detected_finding="SSH_BRUTE_FORCE",
                        finding_description=f"[ {invalid_login_count} ] Failed Logins with Invalid User Detected",
                        timestamp=event.entry_timestamp,
                        source_ip=login_ip,
                        privilege_level=event.entry_privilege_level,
                        associated_username=login_username,
                        associated_hostname=event.entry_hostname,
                        event_count=invalid_login_count
                    )
                ]
        # Return 'nothing' / empty array if event isn't for this detector
        return []

#=====================================
# Detector Class : RootLoginEvent
#=====================================
class RootLoginDetector(BaseDetector):
    def processEvent(self, event, context):
        # Retrieve username
        login_username = event.entry_username
        # Retrieve ip addr
        successful_login_ip = event.entry_source_ip
        login_attempts = context.failed_logins.get(successful_login_ip, 0)

        if event.entry_class == "AUTHENTICATION" and event.entry_subclass == "SUCCESSFUL_LOGIN" and login_username == "root":
            return [
                EventFinding(
                    severity_level="CRITICAL",
                    detected_finding=f"{event.entry_subclass}_ROOT",
                    finding_description=f"Root Login Success after [ {login_attempts} ] Failures",
                    timestamp=event.entry_timestamp,
                    source_ip=successful_login_ip,
                    privilege_level=event.entry_privilege_level,
                    associated_username=login_username,
                    associated_hostname=event.entry_hostname,
                    event_count=context.failed_logins.get(successful_login_ip)
                )
            ]

        # Return 'nothing' / empty array if event isn't for this detector
        return []
