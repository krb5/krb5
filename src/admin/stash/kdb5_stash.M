.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
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
create a Kerberos version 5 principal database.
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
option specifies the key type (as an ascii representation of a decimal
number) of the master key in the database; the default is KEYTYPE_DES.
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
option specifies the encryption type (as an ascii representation of a decimal
number) used for entries in the database; the default is the default
encryption type for the master keytype.
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

