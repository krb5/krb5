.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
.\"
.TH KRB5KDC 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
krb5kdc \- Kerberos V5 KDC
.SH SYNOPSIS
.B krb5kdc
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
.B \-R
.I replycache
] [
.B \-m
]
.br
.SH DESCRIPTION
.I krb5kdc
is the Kerberos version 5 Authentication Service and Key Distribution
Center (AS/KDC).
.PP
The
.B \-r
.I realm
option specifies the realm for which the server should provide service;
by default the realm returned by
.IR krb5_default_local_realm (3)
is used.
.PP
The
.B \-d
.I dbname
option specifies the name under which the principal database can be found; by
default the database is in DEFAULT_DBM_FILE (normally /krb5/principal).
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
.B \-R
option specifies the replay cache to be used; the default is KDCRCACHE
(usually "dfl:krb5kdc_rcache").
.PP
The
.B \-m
option specifies that the master database password should be fetched
from the keyboard rather than from a file on disk.
.SH SEE ALSO
krb5(3), kdb5_create(8), kdb5_stash(8)
.SH BUGS
Doesn't yet do v4 compatibility.

Doesn't yet do inter-realm stuff properly.

It should fork and go into the background when it finishes reading the
master password from the terminal.
