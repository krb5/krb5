.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
.\"
.TH SSERVER 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
sserver \- sample Kerberos version 5 server
.SH SYNOPSIS
.B sserver
.I serverprincipal
.br
.SH DESCRIPTION
.I sserver
is usually executed from the internet daemon (\fIinetd\fR(8)) which
listens on the \fBsample\fR TCP port when a connection from a sample
client is established.  There is a compile-time option to allow it to
run without intervention of the internet daemon.
.PP
.I serverprincipal
names the principal for which the tickets presented by
.I sclient
are expected to be valid; this name is used to fetch the appropriate
service key from the server key store.
.SH SEE ALSO
sclient(1), services(5), inetd(8)
