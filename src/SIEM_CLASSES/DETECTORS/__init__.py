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

# Privilege Escalation
from src.SIEM_CLASSES.DETECTORS.PrivilegeEscalationEvents import (SudoActivityEvent, SensitiveCommandEvent)

# User Management
from src.SIEM_CLASSES.DETECTORS.UserManagementEvents import (UserCreationEvent, UserDeletionEvent, GroupModificationEvent)

# Service Modification
from src.SIEM_CLASSES.DETECTORS.ServiceModificationEvents import (ServiceStopEvent, SecurityControlDisabledEvent, LegacyServiceEnabledEvent)

#=====================================
# Metadata
#=====================================
__version__ = "1.0.0"
SUPPORTED_DETECTORS = [
    SSHBruteForceDetector,
    SuccessfulLoginEvent,
    InvalidUserAuthenticationEvent,
    RootLoginEvent,
    SudoActivityEvent,
    SensitiveCommandEvent,
    UserCreationEvent,
    UserDeletionEvent,
    GroupModificationEvent,
    ServiceStopEvent,
    SecurityControlDisabledEvent,
    LegacyServiceEnabledEvent
]
