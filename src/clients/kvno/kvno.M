.\" Copyright (C) 1998 by the FundsXpress, INC.
.\" 
.\" All rights reserved.
.\" 
.\" Export of this software from the United States of America may require
.\" a specific license from the United States Government.  It is the
.\" responsibility of any person or organization contemplating export to
.\" obtain such a license before exporting.
.\" 
.\" WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
.\" distribute this software and its documentation for any purpose and
.\" without fee is hereby granted, provided that the above copyright
.\" notice appear in all copies and that both that copyright notice and
.\" this permission notice appear in supporting documentation, and that
.\" the name of FundsXpress. not be used in advertising or publicity pertaining
.\" to distribution of the software without specific, written prior
.\" permission.  FundsXpress makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" 
.\" THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
.\" IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
.\" WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
.\"
.\" clients/kvnol/kvno.M
.\" "
.TH KVNO 1
.SH NAME
kvno \- print key version numbers of Kerberos principals
.SH SYNOPSIS
\fBkvno\fP [\fB\-q\fP] [\fB\-h\fP] [\fB\-4\fP\ |\ [\fB-c ccache\fP]\ [\fB\-e etype\fP]]
\fBservice1\fP \fBservice2\fP \fB...\fP
.br
.SH DESCRIPTION
.I Kvno
acquires a service ticket for the specified Kerberos principals and
prints out the key version numbers of each.  
.SH OPTIONS
.TP
.B \-c ccache
specifies the name of a credentials cache to use (if not the default)
.TP
.B \-e etype
specifies the enctype which will be requested for the session key of
all the services named on the command line.  This is useful in certain
backward compatibility situations.
.TP
.B \-q
suppress printing
.TP
.B \-h
prints a usage statement and exits
.TP
.B \-4
specifies that Kerberos version 4 tickets should be acquired and
described.  This option is only available if Kerberos 4 support was
enabled at compilation time.
.SH ENVIRONMENT
.B Kvno
uses the following environment variable:
.TP "\w'.SM KRB5CCNAME\ \ 'u"
.SM KRB5CCNAME
Location of the credentials (ticket) cache.
.TP
.SM KRBTKFILE
Location of the v4 ticket file.
.SH FILES
.TP "\w'/tmp/krb5cc_[uid]\ \ 'u"
/tmp/krb5cc_[uid]
default location of the credentials cache ([uid] is the decimal UID of
the user).
.TP
/tmp/tkt[uid]
default location of the v4 ticket file.
.SH SEE ALSO
kinit(1), kdestroy(1), krb5(3)
