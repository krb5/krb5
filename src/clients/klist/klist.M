.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
.\"
.TH KLIST 1 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
klist \- list cached Kerberos tickets
.SH SYNOPSIS
.B klist
[
.B \-c
.I cachename
] [
.B \-f
]
.br
.SH DESCRIPTION
.I klist
will list the primary principal and Kerberos tickets held in the default
credentials cache, or in the cache
.I cachename
if the
.B \-c
option is used.
If the
.B \-f
option is specified, then the flags present in the ticket will be
printed.  The abbreviations below will be printed:
.nf
.in +.5i
F	Forwardable
f	Forwarded
P	Proxiable
p	Proxy
D	May-post\fBD\fPate
d	Post\fBD\fPated
R	Renewable
I	Initial
.in -.5i
.fi
.PP
The
.IR kinit (1)
manual page specifies how the default credentials cache is selected.
.SH SEE ALSO
kinit(1), kdestroy(1), krb5(3)
.SH BUGS
Does not display srvtabs yet.

Does not list ticket options or lifetimes.
