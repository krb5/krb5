.\" clients/klist/klist.M
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
.TH KLIST 1 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
klist \- list cached Kerberos tickets
.SH SYNOPSIS
.B klist
[
.B \-c
] [
.B \-f
] [
.B \-e
] [
.B \-s
] [
.I cachename
]

.B klist \-k
[
.B \-t
] [
.B \-K 
] [
.I keytabname
]

.br
.SH DESCRIPTION
.I klist
will list the primary principal and Kerberos tickets held 
in a credentials cache if the 
.B \-c
option is used, or in the keytab files if the 
.B \-k
option is used.  By default, the 
.B \-c
option is assumed if neither option is specified on the command line.
.PP
The
.B \-f
option causes
.I klist
to display the flags present in the credentials.
The abbreviations below will be printed:
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
.B \-e
option causes
.I klist
to display the encryption types of the sesison key and the ticket 
for each credential.
.PP
The
.B \-t
option causes
.I klist
to display the time entry timestamps for each keytab entry.
.PP
The
.B \-K
option causes
.I klist
to display the value of the encryption key in each keytab entry.
.PP
If
.I cachename
is not specified, klist will display the credentials in the default 
credentials cache.  The
.IR kinit (1)
manual page specifies how the default credentials cache is selected.
Similarly, if 
.I keytabname
is not specified, the default keytab file shall be used.
.SH SEE ALSO
kinit(1), kdestroy(1), krb5(3)
