.\" krb524/krb524d.M
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
.\" permission.  Furthermore if you modify this software you must label
.\" your software as modified software and not distribute it in such a
.\" fashion that it might be confused with the original M.I.T. software.
.\" M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" "
.TH KRB524D 8
.SH NAME
krb524d \- Version 5 to Version 4 Credentials Conversion Daemon
.SH SYNOPSIS
.B krb524d
[
.B \-m[aster]
|
.B \-k[eytab]
] [
.B \-r
.I realm
] [
.B \-nofork
] [
.B \-p
.I portnum
]
.br
.SH DESCRIPTION
.I krb524d
is the Kerberos Version 5 to Version 4 Credentials Conversion daemon.  
It works in conjuction with a krb5kdc to allow clients to acquire Kerberos 
version 4 tickets from Kerberos version 5 tickets without specifying a password.
.SH OPTIONS
.TP
\fB\-m[aster]\fP
Use the KDC database to convert credentials.  This option cannot be combined with
\fB\-k[eytab]\fP.
.TP
\fB\-k[eytab]\fP
Use the default keytab to convert credentials. This option cannot be combined with
\fB\-m[aster]\fP.  
.TP
\fB\-r\fP \fIrealm\fP
Convert credentials for \fIrealm\fP; by default the realm returned by
.IR krb5_default_local_realm (3)
is used.
.TP
\fB\-nofork\fP
specifies that krb524d not fork on launch.  Useful for debugging purposes.
.TP
\fB\-p\fP \fIportnum\fP 
specifies the default UDP port number which krb524d should listen on for
Kerberos 524 requests.  This value is used when no port is specified in
the KDC profile and when no port is specified in the Kerberos configuration
file.
If no value is available, then the value in /etc/services for service
"krb524" is used.
.SH SEE ALSO
kerberos(1), krb5kdc(8), kdb5_util(8), kdc.conf(5)
