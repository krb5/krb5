.\" clients/kvnol/kvno.M
.\" "
.TH KVNO 1
.SH NAME
kvno \- print key version numbers of Kerberos principals
.SH SYNOPSIS
\fBklist\fP [\fB\-e etype\fP] \fBservice1\fP \fBservice2\fP \fB...\fP
.br
.SH DESCRIPTION
.I Kvno
acquires a service ticket for the specified Kerberos principals and
prints out the key version numbers of each.  
.SH OPTIONS
.TP
.B \-e
specifies the enctype which will be requested for the session key of
all the services named on the command line.  This is useful in certain
backward compatibility situations.
.SH ENVIRONMENT
.B Kvno
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
