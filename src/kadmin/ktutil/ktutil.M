.TH KTUTIL 8
.SH NAME
ktutil \- Kerberos keytab file maintenance utility
.SH SYNOPSIS
.B ktutil
.SH DESCRIPTION
The
.B ktutil
command invokes a subshell from which an administrator can read, write,
or edit entries in a Kerberos V5 keytab or V4 srvtab file.
.SH COMMANDS
.TP
.B list
Displays the current keylist.  Alias:
.BR l .
.TP
\fBread_kt\fP \fIkeytab\fP
Read the Kerberos V5 keytab file
.I keytab
into the current keylist.  Alias: 
.B rkt
.TP
\fBread_st\fP \fIsrvtab\fP
Read the Kerberos V4 srvtab file
.I srvtab
into the current keylist.  Alias:
.BR rst .
.TP
\fBwrite_kt\fP \fIkeytab\fP
Write the current keylist into the Kerberos V5 keytab file
.IR keytab .
Alias:
.BR wkt .
.TP
\fBwrite_st\fP \fIsrvtab\fP
Write the current keylist into the Kerberos V4 srvtab file
.IR srvtab .
Alias:
.BR wst .
.TP
.B clear_list
Clear the current keylist.  Alias:
.BR clear .
.TP
\fBdelete_entry\fP \fIslot\fP
Delets the entry in slot number
.I slot
from the current keylist.  Alais:
.BR delent .
.TP
.BR list_requests
Displays a listing of available commands.  Aliases:
.BR lr ,
.BR ? .
.TP
.B quit
Quits
.BR ktutil .
Aliases:
.BR exit ,
.BR q .
.SH SEE ALSO
kadmin(8), kdb5_util(8)
