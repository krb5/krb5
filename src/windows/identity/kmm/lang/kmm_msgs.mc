; // ** kmm_msgs.mc 

; /* Since .mc files can contain strings from any language, we define
; all our messages in one file in the /lang/ directory instead of
; language specific subdirectories. */

; /* The type is set to (wchar_t *) because that's what we will be
; feeding kherr_report() function. */

MessageIdTypedef=LPWSTR

; /* Severity values as defined in the message definition file are
; currently ignored. */

SeverityNames=(
        Success=0x0
)

LanguageNames=(
        English=0x409:MSG_ENU
)

OutputBase=16

; /* Actual messages start here */

MessageId=1
Severity=Success
SymbolicName=MSG_INITIAL
Language=English
Initial placeholder message
.

MessageId=
SymbolicName=MSG_LOAD_DEFAULT
Language=English
Load default modules
.

MessageId=
SymbolicName=MSG_INIT_MODULE
Language=English
Initializing module [%1]
.

MessageId=
SymbolicName=MSG_IM_GET_CONFIG
Language=English
Can't get configuration for modules
.

MessageId=
SymbolicName=MSG_IM_NOT_PREINIT
Language=English
Module is not in PREINIT state.  Current state=[%1!d!]
.

MessageId=
SymbolicName=MSG_IM_NOT_REGISTERED
Language=English
Module is not registered
.

MessageId=
SymbolicName=MSG_IM_DISABLED
Language=English
Module is disabled
.

MessageId=
SymbolicName=MSG_IM_MAX_FAIL
Language=English
Module has failed too many times
.

MessageId=
SymbolicName=MSG_IM_INVALID_MODULE
Language=English
The DLL containing the module was not of the correct format.
.

MessageId=
SymbolicName=MSG_IM_INCOMPATIBLE
Language=English 
The DLL containing the module was not compatible with this version of NetIDMgr.
.

Messageid=
SymbolicName=MSG_IM_NOT_FOUND
Language=English
Module binary was not found.  Checked path [%1]
.

MessageId=
SymbolicName=MSG_IM_NO_ENTRY
Language=English
Entry point not found.  Checked entry point [%1]
.

MessageId=
SymbolicName=MSG_IM_INIT_FAIL
Language=English
Module initialization entry point returned failure code [%1!d!]
.

MessageId=
SymbolicName=MSG_IM_NO_PLUGINS
Language=English
No plugins were registerd by the module
.

MessageId=
SymbolicName=MSG_IM_MOD_STATE
Language=English
Module [%1] is in state [%2!d!]
.

MessageId=
SymbolicName=MSG_IMERR_TITLE
Language=English
Failed to load module %1!s!
.

MessageId=
SymbolicName=MSG_IMERR_SUGGEST
Language=English
The following information may help resolve this issue:

%2!s!
.

MessageId=
SymbolicName=MSG_IP_TASK_DESC
Language=English
Initializing plugin [%1]
.

MessageId=
SymbolicName=MSG_IP_GET_CONFIG
Language=English
Can't get configuration for plugins
.

MessageId=
SymbolicName=MSG_IP_NOT_REGISTERED
Language=English
The plugin is not registered
.

MessageId=
SymbolicName=MSG_IP_DISABLED
Language=English
The plugin is disabled
.

MessageId=
SymbolicName=MSG_IP_HOLD
Language=English
Placing plugin [%1] on hold
.

MessageId=
SymbolicName=MSG_IP_STATE
Language=English
Leaving plugin [%1] in state [%2!d!]
.

MessageId=
SymbolicName=MSG_IP_EXITING
Language=English
The plugin [%1] is in error state [%2!d!].  Exiting plugin.
.

MessageId=
SymbolicName=MSG_RMI_NOT_FOUND
Language=English
Can't get file version information for path [%1!s!]
.

MessageId=
SymbolicName=MSG_RMI_NO_TRANS
Language=English
Can't get version resource tranlations list for path [%1!s!]
.

MessageId=
SymbolicName=MSG_RMI_NO_LOCAL
Language=English
The list of version translations were empty or did not contain a resource for the current user or system locale.
.

MessageId=
SymbolicName=MSG_RMI_RES_MISSING
Language=English
Required resource %1!s! missing
.

MessageId=
SymbolicName=MSG_RMI_MOD_MISMATCH
Language=English
The module name specified in the resource is [%1!s!] while the module name as registered is [%2!s!]
.

MessageId=
SymbolicName=MSG_RMI_RES_TOO_LONG
Language=English
The resource %1!s! is malformed or too long
.

MessageId=
SymbolicName=MSG_RMI_API_MISMATCH
Language=English
The module was compile for API version %1!d!.  However the current API version is %2!d!.
.

MessageId=
SymbolicName=MSG_PB_START
Language=English
Starting plugin [%1!s!]
.

MessageId=
SymbolicName=MSG_PB_INVALID_CODE_PTR
Language=English
The plugin is no longer valid.  This maybe because the module containing the plugin was unloaded.
.

MessageId=
SymbolicName=MSG_PB_INIT_RV
Language=English
Initialization of the plugin returned code %1!d!.
.

MessageId=
SymbolicName=MSG_PB_INIT_FAIL
Language=English
Initialization of the %1!s! plugin failed.  The plugin will be unloaded and any functionality provided will not be available.
.

MessageId=
SymbolicName=MSG_PB_INIT_FAIL_S
Language=English
Plugin %1!s! failed to initialize
.

MessageId=
SymbolicName=MSG_PB_INIT_FAIL_G
Language=English
Details for plugin:
Description: %2!s!
Module: %3!s!
Support: %4!s!
.

MessageId=
SymbolicName=MSG_PB_INIT_DONE
Language=English
Plugin running
.
