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
from src.SIEM_CLASSES.DETECTORS.AuthenticationDetector import (SSHBruteForceDetector, SuccessfulLoginDetector, InvalidUserAuthenticationDetector, RootLoginDetector)

# User Management
from src.SIEM_CLASSES.DETECTORS.UserManagementDetector import (UserCreationDetector, UserDeletionDetector, PasswordChangeDetector)

# Privilege Escalation
from src.SIEM_CLASSES.DETECTORS.PrivilegeEscalationDetector import (UserAddedToSudoDetector, UserAddedToWheelDetector)

# Credential Access
from src.SIEM_CLASSES.DETECTORS.CredentialAccessDetector import (ShadowFileAccessDetector, PasswdFileAccessDetector)

# Defense Evasion
from src.SIEM_CLASSES.DETECTORS.DefenseEvasionDetector import (AuditdStoppedDetector, FirewalldStoppedDetector, TelnetEnabledDetector)

# Suspicious Commands
from src.SIEM_CLASSES.DETECTORS.SuspiciousCommandDetector import (NetcatInstallationDetector, NmapInstallationDetector, CurlDownloadDetector, WgetDownloadDetector, SCPFileTransferDetector, TarCreationDetector)

#=====================================
# Metadata
#=====================================
__version__ = "1.0.0"
SUPPORTED_DETECTORS = [
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
]
