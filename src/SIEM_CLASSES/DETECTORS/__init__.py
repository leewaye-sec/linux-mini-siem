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
from .AuthenticationDetector import (SSHBruteForceDetector, SuccessfulLoginDetector, InvalidUserAuthenticationDetector, RootLoginDetector)

# User Management
from .UserManagementDetector import (UserCreationDetector, UserDeletionDetector, PasswordChangeDetector)

# Privilege Escalation
from .PrivilegeEscalationDetector import (UserAddedToSudoDetector, UserAddedToWheelDetector)

# Credential Access
from .CredentialAccessDetector import (ShadowFileAccessDetector, PasswdFileAccessDetector)

# Defense Evasion
from .DefenseEvasionDetector import (AuditdStoppedDetector, FirewalldStoppedDetector, TelnetEnabledDetector)

# Suspicious Commands
from .SuspiciousCommandDetector import (NetcatInstallationDetector, NmapInstallationDetector, CurlDownloadDetector, WgetDownloadDetector, SCPFileTransferDetector, TarCreationDetector)

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
