.\"
.\" clients/kvnol/kdeltkt.M
.\" "
.TH KDELTKT 1
.SH NAME
kdeltkt \- delete one or more service tickets from the credentials cache
.SH SYNOPSIS
\fBkdeltkt\fP [\fB\-h\fP] [\fB\-c ccache\fP] [\fB\-e etype\fP] [\fB\-f flags\fP] 
\fBservice1\fP \fBservice2\fP \fB...\fP
.br
.SH DESCRIPTION
.I kdeltkt
deletes the specified service tickets from the credentials cache
.SH OPTIONS
.TP
.B \-c
specifies the credentials cache from which service tickets will be deleted.
if no cache is specified, the default cache is used.
.TP
.B \-e
specifies the session key enctype of the service tickets you wish to delete.
.TP
.B \-h
prints a usage statement and exits
.SH ENVIRONMENT
.B kdeltkt
uses the following environment variable:
.TP "\w'.SM KRB5CCNAME\ \ 'u"
.SM KRB5CCNAME
Location of the credentials (ticket) cache.
.SH FILES
.TP "\w'/tmp/krb5cc_[uid]\ \ 'u"
/tmp/krb5cc_[uid]
default location of the credentials cache ([uid] is the decimal UID of
the user).
.SH SEE ALSO
kinit(1), kdestroy(1), krb5(3)
