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
