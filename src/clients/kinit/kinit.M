.\" clients/kinit/kinit.M
.\"
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" Export of this software from the United States of America may
.\"   require a specific license from the United States Government.
.\"   It is the responsibility of any person or organization contemplating
.\"   export to obtain such a license before exporting.
.\" 
.\" WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
.\" distribute this software and its documentation for any purpose and
.\" without fee is hereby granted, provided that the above copyright
.\" notice appear in all copies and that both that copyright notice and
.\" this permission notice appear in supporting documentation, and that
.\" the name of M.I.T. not be used in advertising or publicity pertaining
.\" to distribution of the software without specific, written prior
.\" permission.  M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" 
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
.B \-s
.I starttime
] [
.B \-v
] [
.B \-p
] [
.B \-f
] [
.B \-r
.I rlife
] [
.B \-R
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
option specifies the lifetime to be requested for the ticket;
if this option is not specified, the default ticket lifetime (configured
by each site) is used instead.
.PP
The
.B \-s
option specifies the start time, and causes you to get a postdated ticket. 
Postdated tickets are issued with the 
.I invalid
flag set, and needs to be fed back to the kdc before use. This may be
accomplished by using the 
.B \-v
option. 
.PP
The
.B \-p
option specifies that the PROXIABLE option should be requested for the
ticket.
.PP
The
.B \-f
option specifies that the FORWARDABLE option should be requested for the
ticket.
.PP
The
.B \-r
.I rlife
option specifies that the RENEWABLE option should be requested for the
ticket, and specifies the desired total lifetime of the ticket. To renew
the ticket, the 
.B \-R
option is used. Note that you must renew the ticket before it has
expired. 
.PP
The
.B \-c
option can be used to specify an alternate credentials cache; if this
option is not used, the default cache is used.  Any contents of the
cache are destroyed by
.IR kinit .
.PP
The
.B \-s
option can be used to specify an alternate service name to use when
getting initial tickets.
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
