.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1991 by the Massachusetts Institute of Technology.
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
.TH KDB5_CONVERT 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kdb5_convert \- convert a v4 Kerberos principal database to a v5 database
.SH SYNOPSIS
.B kdb5_convert
[
.B \-r
.I realm
] [
.B \-d
.I v5dbname
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
.B \-n
]
.B \-D
.I v4dbname
.br
.B kdb5_convert
[
.B \-r
.I realm
] [
.B \-d
.I v5dbname
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
.B \-n
] 
.B \-f
.I v4dumpfile
.br
.SH DESCRIPTION
.I kdb5_convert
is used to create a Kerberos version 5 principal database and fill it
with entries from a Kerberos version 4 principal database.  The user is
normally prompted two passwords: the version 5 master password, which
will be used to generate an encryption key under which all entries are
stored (in order to provide some security against database theft), and
the version 4 master password, which is used to access the entries in
the version 4 database.
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
.I v5dbname
option specifies the name under which the version 5 principal database is to be
created; by default the database is in DEFAULT_DBM_FILE (normally
/krb5/principal).
.PP
If the
.B \-t
option is used \fIkdb5_convert\fR will create a temporary database and
rename it into place after it is loaded so that a server using the database
can continue running.  It is an error for the target database to exist
if this option is not used.
.PP
The
.B \-D
.I v4dbname
option specifies the name under which the version 4 principal database
is to be found.
.PP
The
.B \-f
.I v4dumpfile
option specifies that the version 4 database should be loaded from the
dump file rather than from a principal database.
.PP
The
.B \-k
.I keytype
option specifies the key type of the master key in the database; the default
is KEYTYPE_DES.
.PP
The
.B \-M
.I mkeyname
option specifies the principal name for the master key in the database;
the default is KRB5_KDB_M_NAME (usually "K/M" in the local realm).
.PP
The
.B \-e
.I enctype
option specifies the encryption type to be used when placing entries in
the database; the default is the default encryption type for the master
keytype.
.PP
The
.B \-n
option specifies that the master key for the v4 database should be
entered manually rather than fetched from the normal v5 master key file.
The
.B \-K
option specifies that the master key for the v5 (new) database should
be entered manually rather than fetched from the normal v4 master key file.
When the
.B \-v
option is used, \fIkdb5_convert\fR prints the name of each principal it
encounters in the old database and whether the principal is being copied
to the new database or ignored.
.SH SEE ALSO
krb5(3), krb5kdc(8)
.SH BUGS
Doesn't have flexibility about expiration times. 
.sp
When the underlying databases are built on the old DBM (not NDBM), the
.B \-D
option is not allowed, i.e. the
conversion must be done from a dump file rather than from a DBM
database, due to restrictions in the old DBM implementation.
