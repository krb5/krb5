.\"
.\" clients/kvnol/kcpytkt.M
.\" "
.TH KCPYTKT 1
.SH NAME
kcpytkt \- copies one or more service tickets between credentials caches
.SH SYNOPSIS
\fBkcpytkt\fP [\fB\-h\fP] [\fB\-c source_ccache\fP] [\fB\-e etype\fP] [\fB\-f flags\fP] 
\fBdest_ccache\fP \fBservice1\fP \fBservice2\fP \fB...\fP
.br
.SH DESCRIPTION
.I kcpytkt
copies the specified service tickets to the destination credentials cache
.SH OPTIONS
.TP
.B \-c
specifies the source credentials cache from which service tickets will be.
copied.  if no ccache is specified, the default ccache is used.
.TP
.B \-e
specifies the session key enctype of the service tickets you wish to delete.
.TP
.B \-h
prints a usage statement and exits
.SH ENVIRONMENT
.B kcpytkt
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
