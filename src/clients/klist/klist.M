.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" Export of this software from the United States of America is assumed
.\"   to require a specific license from the United States Government.
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
