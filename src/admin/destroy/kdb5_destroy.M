.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
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
destroys a Kerberos principal database.
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
