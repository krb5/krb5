.\" clients/kdestroy/kdestroy.M
.\"
.\" Copyright 1992 by the Massachusetts Institute of Technology.
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
.TH KDESTROY 1 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kdestroy \- destroy Kerberos tickets
.SH SYNOPSIS
.B kdestroy
[
.B \-c
.I cachename
]
.SH DESCRIPTION
The
.I kdestroy
utility destroys the user's active
Kerberos authorization tickets by writing zeros to the specified
credentials cache that contains them.  If the credentials cache is not
specified, the default credentials cache is destroyed.
.PP
In the Athena workstation environment, the
.I login 
or 
.I Xlogin
program automatically destroys your tickets when you
end a workstation session.
If your site does not provide a similar ticket-destroying mechanism,
you can place the
.I kdestroy
command in your
.I .logout
file so that your tickets are destroyed automatically
when you logout.
.PP
.SH SEE ALSO
kerberos(1), kinit(1), klist(1)
.SH BUGS
.PP
Only the tickets in the user's current ticket file are destroyed.
Separate ticket files are used to hold root instance and password
changing tickets.  These files should probably be destroyed too, or
all of a user's tickets kept in a single ticket file.
