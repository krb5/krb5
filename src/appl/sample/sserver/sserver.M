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
.TH SSERVER 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
sserver \- sample Kerberos version 5 server
.SH SYNOPSIS
.B sserver
[
.I server_port
]
.br
.SH DESCRIPTION
.I sserver
is usually executed from the internet daemon (\fIinetd\fR(8)) which
listens on the \fBsample\fR TCP port when a connection from a sample
client is established.  There is a compile-time option to allow it to
run without intervention of the internet daemon.
.PP
.I server_port
is an optional argument; if specified, 
.I sserver
will listen on the specified port and wait for a connection.  It is used for
debugging when it is inconvenient to run the sample server out of inetd.
.SH SEE ALSO
sclient(1), services(5), inetd(8)
