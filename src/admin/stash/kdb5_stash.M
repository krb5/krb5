.\" admin/stash/kdb5_stash.M
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
.TH KDB5_STASH 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kdb5_stash \- store a principal database master key on disk
.SH SYNOPSIS
.B kdb5_stash
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
.B \-f
.I keyfile
]
.br
.SH DESCRIPTION
.I kdb5_stash
stores a Kerberos principal database master key in a file;
this key may subsequently be used for unattended re-start of a Kerberos
V5 KDC.
The user is prompted for the master password, which will be verified
against the database, and then stored in a file.
.PP
The
.B \-r
.I realm
option specifies the realm for which the database key should be stored;
by default the realm returned by
.IR krb5_default_local_realm (3)
is used.
.PP
The
.B \-d
.I dbname
option specifies the name under which the principal database is
stored; by default the database is in DEFAULT_DBM_FILE (normally
/krb5/principal).
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
the default is KRB5_KDB_M_NAME (usually "K/M" in the KDC's realm).
.PP
The
.B \-e
.I enctype
option specifies the encryption type used for entries in the database; the
default is the default encryption type for the master keytype.
.PP
The
.B \-f
option specifies the file in which the master key should be stored; the
default is DEFAULT_KEYFILE_STUB ("/.k5." concatenated with the realm name).
.SH SEE ALSO
krb5(3), krb5kdc(8), kdb5_create(8)
.SH BUGS
Allows an intruder to gain access to the entire database if the security
of the KDC system is breached.

