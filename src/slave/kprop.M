.\" slave/kprop.M
.\"
.\" Copyright 1992 by the Massachusetts Institute of Technology.
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
.TH KPROP 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kprop \- propagate a Kerberos V5 principal database to a slave server
.SH SYNOPSIS
.B kprop
[
.B \-r
.I realm
] [
.B \-f
.I file
] [
.B \-d
] [
.B \-P
.I port
] [
] [
.B \-s
.I srvtab
] 
.I slave_host
.br
.SH DESCRIPTION
.I kprop
is used to propagate a Kerberos V5 database dump file from the
master Kerberos server to a slave Kerberos server, which is specfieid
by
.I slave_host.  
This is done by transmitting the dumped database file to the slave
server over an encrypted, secure channel.  The dump file must be
created by kdb5_edit, and is normally KPROP_DEFAULT_FILE
(/krb5/slave_datatrans).  The location of the file can be overriden by
the -f option.

.PP
The
.B \-r
.I realm
option specifies the realm of the master server;
by default the realm returned by
.IR krb5_default_local_realm (3)
is used.
.PP
The
.B \-f
.I file
option the filename where the dumped principal database file is to be
found; by default the dumped database file is KPROP_DEFAULT_FILE
(normally /krb5/slave_datatrans).
.PP
The
.B \-P
.I port
option allows one to override the default port to contact the 
.I kpropd
server on the remote host.
.SH SEE ALSO
kpropd(8), kdb5_edit(8), krb5kdc(8)
