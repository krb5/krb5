.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
.\"
.TH KDB5_EDIT 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kdb5_edit \- edit a Kerberos V5 principal database
.SH SYNOPSIS
.B kdb5_edit
[
.B \-r
.I realm
] [
.B \-d
.I dbname
] [
.B \-k
.I keytype
] [
.B \-M
.I mkeyname
] [
.B \-e
.I enctype
] [
.B \-m
]
.br
.SH DESCRIPTION
.I kdb5_edit
allows an administrator to add, delete, and edit entries in a Kerberos
version 5 principal database.
After the master key is verified, the administrator is placed into a
shell-like command loop, from which he may issue commands to modify the
database.  '?' lists the commands available; 'exit' or 'quit' exits the
program.
.PP
The
.B \-r
.I realm
option specifies the realm of the database;
by default the realm returned by
.IR krb5_default_local_realm (3)
is used.
.PP
The
.B \-d
.I dbname
option specifies the name under which the principal database is stored;
by default the database is in DEFAULT_DBM_FILE (defined in <krb5/osconf.h>).
.PP
The
.B \-k
.I keytype
option specifies the key type (as an ascii representation of a decimal
number) of the master key in the database; the default is
DEFAULT_KDC_KEYTYPE (defined in <krb5/osconf.h>).
.PP
The
.B \-M
.I mkeyname
option specifies the principal name for the master key in the database;
the default is KRB5_KDB_M_NAME (defined in <krb5/kdb.h>).
.PP
The
.B \-e
.I enctype
option specifies the encryption type (as an ascii representation of a decimal
number) to be used when placing entries in
the database; the default is DEFAULT_KDC_ETYPE (defined in <krb5/osconf.h>).
.PP
The
.B \-m
option specifies that the master database password should be fetched
from the keyboard rather than from a file on disk.
.SH SEE ALSO
krb5(3), krb5kdc(8), ss(3)
.SH BUGS
This man page needs to document the ss commands.
