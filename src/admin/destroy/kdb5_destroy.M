.\" admin/destroy/kdb5_destroy.M
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
.TH KDB5_DESTROY 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kdb5_destroy \- destroy a Kerberos principal database
.SH SYNOPSIS
.B kdb5_destroy
[
.B \-d
.I dbname
]
.br
.SH DESCRIPTION
.I kdb5_destroy
destroys a Kerberos principal database, i.e. all of the data is
overwritten and then the file is removed.
The user is prompted to confirm deletion of the database.
.PP
The
.B \-d
.I dbname
option specifies the name under which the principal database is
stored; by default the database is in DEFAULT_DBM_FILE (normally
/krb5/principal).
.SH SEE ALSO
kdb5_create(8)
