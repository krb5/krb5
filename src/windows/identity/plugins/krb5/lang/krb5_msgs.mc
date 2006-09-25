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
SymbolicName=MSG_CTX_INITAL_CREDS
Language=English
Obtaining initial Krb5 credentials
.

MessageId=
SymbolicName=MSG_CTX_RENEW_CREDS
Language=English
Renewing Krb5 credentials
.

MessageId=
SymbolicName=MSG_ERR_UNKNOWN
Language=English
An unknown error has occurred.
.

MessageId=
SymbolicName=MSG_ERR_PR_UNKNOWN
Language=English
You have entered an unknown username/instance/realm combination.
.

MessageId=
SymbolicName=MSG_ERR_TKFIL
Language=English
The tickets could not be accessed from the memory location where they were stored.
.

MessageId=
SymbolicName=MSG_ERR_S_TKFIL
Language=English
This may be due to a problem with the memory where your tickets are stored.  Restarting your computer might be worth a try.
.

MessageId=
SymbolicName=MSG_ERR_CLOCKSKEW
Language=English
Your computer's clock is out of sync with the Kerberos server.
.

MessageId=
SymbolicName=MSG_ERR_S_CLOCKSKEW
Language=English
Synchronize your clock withe the Kerberos server.
.

MessageId=
SymbolicName=MSG_ERR_KDC_CONTACT
Language=English
Cannot contact the Kerberos server for the requested realm.
.
 
MessageId=
SymbolicName=MSG_ERR_INSECURE_PW
Language=English
You have entered an insecure or weak password.
.

MessageId=
SymbolicName=MSG_ERR_NO_IDENTITY
Language=English
There were no identities for which to renew credentials.
.

MessageId=
SymbolicName=MSG_CTX_PASSWD
Language=English
Changing Kerberos 5 Password
.

MessageId=
SymbolicName=MSG_PWD_UNKNOWN
Language=English
Unknown error
.

MessageId=
SymbolicName=MSG_PWD_NOT_SAME
Language=English
The new passwords are not the same.
.

MessageId=
SymbolicName=MSG_PWD_S_NOT_SAME
Language=English
The new password is asked for twice to protect against a mistake when setting the new password.  Both instances of the new password must be the same.  Please correct this and try again.
.

MessageId=
SymbolicName=MSG_PWD_SAME
Language=English
The new and the old passwords are the same.
.

MessageId=
SymbolicName=MSG_PWD_S_SAME
Language=English
Please type a new password to continue.
.

MessageId=
SymbolicName=MSG_PWD_NO_IDENTITY
Language=English
There are no identities selected.
.

MessageId=
SymbolicName=MSG_PWD_S_NO_IDENTITY
Language=English
Please select an identity to change the password.
.

MessageId=
SymbolicName=MSG_ERR_S_INTEGRITY
Language=English
This is commonly caused by an incorrect password.  Please verify that the password is correct and note that passwords are case sensitive.
.

MessageId=
SymbolicName=MSG_ERR_CTX_DESTROY_CREDS
Language=English
Destroying Krb5 tickets
.

MessageId=
SymbolicName=MSG_ERR_NETDOWN
Language=English
A network connection is unavailable
.

MessageId=
SymbolicName=MSG_ERR_S_NETRETRY
Language=English
Please check your network connection or contact your network administrator for assistance.
.

MessageId=
SymbolicName=MSG_ERR_TEMPDOWN
Language=English
A temporary network error caused the operation to fail
.

MessageId=
SymbolicName=MSG_ERR_S_TEMPDOWN
Language=English
Please try again in a few minutes
.

MessageId=
SymbolicName=MSG_ERR_NOHOST
Language=English
A server could not be reached
.

MessageId=
SymbolicName=MSG_ERR_S_NOHOST
Language=English
This can be caused by the server being unavailable, network errors, or improper configuration.  Please try again or contact your administrator for assistance.
.

MessageId=
SymbolicName=MSG_
Language=English
.
