.\" kdc/krb5kdc.M
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
.\" "
.so man1/header.doc
.TH KRB5KDC 8 \*h
.SH NAME
krb5kdc \- Kerberos V5 KDC
.SH SYNOPSIS
.B krb5kdc
[
.B \-d
.I dbname
] [
.B \-k
.I keytype
] [
.B \-M
.I mkeyname
] [
.B \-p
.I portnum
] [
.B \-s
.I portnum
] [
.B \-m
] [
.B \-r
.I realm
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
default the database is in DEFAULT_DBM_FILE.
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
.B \-p
.I portnum
option specifies the default UDP port number which the KDC should listen on for
Kerberos version 5 requests.  This value is used when no port is specified in
the KDC profile and when no port is specified in the Kerberos configuration
file.
If no value is available, then the value in /etc/services for service
"kerberos" is used.
.PP
The
.B \-s
.I portnum
option specifies the default UDP port number which the KDC should listen on for
Kerberos version 4 requests.  This value is used when no port is specified in
the kdc profile and when no port is specified in the Kerberos configuration
file.
If no value is available, then the value in /etc/services for service
"kerberos-sec" is used.
.PP
The
.B \-m
option specifies that the master database password should be fetched
from the keyboard rather than from a file on disk.
.PP
The KDC may service requests for multiple realms (maximum 32 realms).  The
realms are listed on the command line.  Per-realm options that can be
specified on the command line pertain for each realm that follows it and are
superceded by subsequent definitions of the same option.  For example, 
.PP
.B krb5kdc
.B \-p
.I 2001
.B \-r
.I REALM1
.B \-p
.I 2002
.B \-r
.I REALM2
.B \-r
.I REALM3
.PP
specifies that the KDC listen on port 2001 for REALM1 and on port 2002 for
REALM2 and REALM3.  Additionally, per-realm parameters may be specified in the
.I kdc.conf
file.  The location of this file may be specified by the
.I KRB5_KDC_PROFILE
environment variable.  Parameters specified in this file take precedence over
options specified on the command line.  See the
.I kdc.conf(5)
description for further details.
.SH SEE ALSO
krb5(3), kdb5_create(8), kdb5_stash(8), kdc.conf(5)
.SH BUGS

It should fork and go into the background when it finishes reading the
master password from the terminal.
