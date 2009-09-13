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
\fBkvno\fP [\fB\-q\fP] [\fB\-h\fP] [\fB-c ccache\fP]\ [\fB\-e etype\fP]
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
.B \-P
specifies that the
.B service1 service2 ...
arguments are to be treated as services for which credentials should
be acquired using constrained delegation. This option is only valid
when used in conjunction with protocol transition.
.TP
.B \-S sname
specifies that krb5_sname_to_principal() will be used to build
principal names.  If this flag is specified, the
.B service1 service2 ...
arguments are interpreted as hostnames (rather than principal names),
and
.B sname
is interpreted as the service name.
.TP
.B \-U for_user
specifies that protocol transition (S4U2Self) is to be used to acquire
a ticket on behalf of
.B for_user.
If constrained delegation is not requested, the service name
must match the credentials cache client principal.
.SH ENVIRONMENT
.B Kvno
uses the following environment variable:
.TP "\w'.SM KRB5CCNAME\ \ 'u"
.SM KRB5CCNAME
Location of the credentials (ticket) cache.
.SH FILES
.TP "\w'/tmp/krb5cc_[uid]\ \ 'u"
/tmp/krb5cc_[uid]
default location of the credentials cache ([uid] is the decimal UID of
the user).
.SH SEE ALSO
kinit(1), kdestroy(1), krb5(3)
