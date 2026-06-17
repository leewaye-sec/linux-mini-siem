#==========================================================================
#
#           File : __init__.py
#        Project : Mini-SIEM
#    Description :
#                  - Creates DETECTORS package / API
#                  - Imports for AuthenticationEvents, PrivilegeEscalationEvents,
#                       UserManagementEvents, ServiceModificationEvents
#                  - Some metadata definitions
#
#==========================================================================
#=====================================
# Detectors class imports
#=====================================
# Authentication
from src.SIEM_CLASSES.DETECTORS.AuthenticationEvents import (SSHBruteForceDetector, SuccessfulLoginEvent, InvalidUserAuthenticationEvent, RootLoginEvent)

# User Management
from src.SIEM_CLASSES.DETECTORS.UserManagementEvents import (UserCreationEvent, UserDeletionEvent, PasswordChangeEvent)

# Privilege Escalation
from src.SIEM_CLASSES.DETECTORS.PrivilegeEscalationEvents import (UserAddedToSudoEvent, UserAddedToWheelEvent)

# Credential Access
from src.SIEM_CLASSES.DETECTORS.CredentialAccessEvents import (ShadowFileAccessEvent, PasswdFileAccessEvent)

# Defense Evasion
from src.SIEM_CLASSES.DETECTORS.DefenseEvasionEvents import (AuditdStoppedEvent, FirewalldStoppedEvent, TelnetEnabledEvent)

# Suspicious Commands
from src.SIEM_CLASSES.DETECTORS.SuspiciousCommandEvents import (NetcatInstallationEvent, NmapInstallationEvent, CurlDownloadEvent, WgetDownloadEvent)

#=====================================
# Metadata
#=====================================
__version__ = "1.0.0"
SUPPORTED_DETECTORS = [
    SSHBruteForceDetector,
    SuccessfulLoginEvent,
    InvalidUserAuthenticationEvent,
    RootLoginEvent,
    UserCreationEvent,
    UserDeletionEvent,
    PasswordChangeEvent,
    UserAddedToSudoEvent,
    UserAddedToWheelEvent,
    ShadowFileAccessEvent,
    PasswdFileAccessEvent,
    AuditdStoppedEvent,
    FirewalldStoppedEvent,
    TelnetEnabledEvent,
    NetcatInstallationEvent,
    NmapInstallationEvent,
    CurlDownloadEvent,
    WgetDownloadEvent
]
