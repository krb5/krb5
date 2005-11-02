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
