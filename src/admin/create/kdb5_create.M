.\" $Source$
.\" $Author$
.\" $Id$
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
.TH KDB5_CREATE 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kdb5_create \- create a new Kerberos V5 principal database
.SH SYNOPSIS
.B kdb5_create
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
]
.br
.SH DESCRIPTION
.I kdb5_create
is used to create an empty Kerberos version 5 principal database.
The user is prompted for the master password, which will be used to
generate an encryption key under which all entries are stored (in order
to provide some security against database theft).
.PP
The
.B \-r
.I realm
option specifies the realm for which the database should be created;
by default the realm returned by
.IR krb5_default_local_realm (3)
is used.
.PP
The
.B \-d
.I dbname
option specifies the name under which the principal database is to be
created; by default the database is in DEFAULT_DBM_FILE (normally
/krb5/principal).
.PP
The
.B \-k
.I keytype
option specifies the key type of the master key in the database.
.PP
The
.B \-M
.I mkeyname
option specifies the principal name for the master key in the database;
the default is KRB5_KDB_M_NAME (usually "K/M" in the KDC's realm).
.PP
The
.B \-e
.I enctype
option specifies the encryption type to be used when placing entries in
the database.
keytype.
.SH SEE ALSO
krb5(3), krb5kdc(8)
.SH BUGS
Doesn't have flexibility about expiration times.
