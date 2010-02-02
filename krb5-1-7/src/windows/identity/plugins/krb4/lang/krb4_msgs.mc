; // ** krb5_msgs.mc

; /* Since .mc files can contain strings from any language, we define
; all our messages in one file in the /lang/ directory instead of
; language specific subdirectories. */

; /* The type is set to (wchar_t *) because that's what we will be
; feeding kherr_report() function. */

; // MessageIdTypedef=LPWSTR

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
SymbolicName=MSG_K4_NEW_CREDS
Language=English
Getting new Krb4 credentials for [%1!s!] using method [%2!d!]
.

MessageId=
SymbolicName=MSG_K4_RENEW_CREDS
Language=English
Renewing Krb4 credentials for [%1!s!] using method [%2!d!]
.

MessageId=
SymbolicName=MSG_K4_TRY_K524
Language=English
Trying Krb524 ...
.

MessageId=
SymbolicName=MSG_K4_TRY_PASSWORD
Language=English
Trying Password ...
.

