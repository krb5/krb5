.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
.\"
.TH SCLIENT 1 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
sclient \- sample Kerberos version 5 client
.SH SYNOPSIS
.B sclient
.I remotehost
.br
.SH DESCRIPTION
.I sclient
will contact a sample server (\fIsserver\fR(8)) and authenticate to it
using Kerberos version 5 tickets, then display the server's response.
.SH SEE ALSO
kinit(1), sserver(8)
.SH BUGS
