.\" appl/sample/sclient/sclient.M
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
