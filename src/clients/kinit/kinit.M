.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
.\"
.TH KINIT 1 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kinit \- obtain and cache Kerberos ticket-granting ticket
.SH SYNOPSIS
.B kinit
[
.B \-l
.I lifetime
] [
.B \-p
] [
.B \-r
] [
.B \-c
.I cachename
]
.I principal
.br
.SH DESCRIPTION
.I kinit
obtains and caches an initial ticket-granting ticket for
.IR principal .
The
.B \-l
option specifies the lifetime to be requested for the ticket; if this
option is not specified, the default ticket lifetime (configured by each site)
is used instead.
.PP
The
.B \-p
option specifies that the PROXIABLE option should be requested for the
ticket.
.PP
The
.B \-r
option specifies that the RENEWABLE option should be requested for the
ticket.
.PP
The
.B \-c
option can be used to specify an alternate credentials cache; if this
option is not used, the default cache is used.  Any contents of the
cache are destroyed by
.IR kinit .
.PP
The default credentials cache may vary between systems; however, if the
.B KRB5CCNAME
environment variable is set, its value is used to name the default
ticket cache.
.SH FILES
.TP 2i
/tmp/krb5cc_[uid]
as the normal default credentials cache ([uid] is the decimal UID of the user).
.SH SEE ALSO
klist(1), kdestroy(1), krb5(3)
.SH BUGS
