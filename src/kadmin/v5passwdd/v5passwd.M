.\" kadmin/v5passwdd/v5passwd.M
.\" 
.\" Copyright 1995 by the Massachusetts Institute of Technology.
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
.\" permission.  Furthermore if you modify this software you must label
.\" your software as modified software and not distribute it in such a
.\" fashion that it might be confused with the original M.I.T. software.
.\" M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" 
.\"
.TH V5PASSWD 1
.SH NAME
v5passwd \- change a user's Kerberos password
.SH SYNOPSIS
.B v5passwd
[
.B \-u
.IR username[/instance][@realm]
]
.SH DESCRIPTION
The 
.I v5passwd
command is used to change a Kerberos principal's password using the
older administrative protocol. 

If the
.I \-u
option is specified, a partially or fully qualified Kerberos principal may
be supplied.  Otherwise, the principal name is derived from the identity
of the user invoking the
.I v5passwd
command.

.PP
The
.I v5passwd
command prompts for the current Kerberos password,  which is verified by the
Kerberos server.  If the old password is correct, the user is prompted twice
for the new password.  Success or failure is indicated by messages printed
out by
.I v5passwd.


.SH FILES
.TP 2i
/tmp/tkt_kpw_[uid]
the temporary credentials cache ([uid] is the decimal UID of the user) for
the lifetime of the password changing operation.
.SH SEE ALSO
kadmin(8), kadmind(8), v5passwdd(8)
.SH BUGS
