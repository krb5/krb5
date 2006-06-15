.\" kdc/fakeka.M
.\"
.\" Copyright 2005 by the Massachusetts Institute of Technology.
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
.TH FAKEKA 8
.SH NAME
fakeka \- Fake kaserver for AFS clients
.SH SYNOPSIS
\fBfakeka\fP [\fB\-dm\fP] [\fB\-c\fP \fIcell\fP] [\fB\-f\fP \fIforwarder\fP]
[\fB\-l\fP \fBfacility\fP] [\fB\-p\fP \fBport\fP] [\fB\-r\fP \fIrealm\fP]
.br
.SH DESCRIPTION
.I fakeka
is a fake kaserver that speaks just enough of the AFS RX protocol to make
klog work.  It is used in conjunction with a Kerberos V5 KDC to support
existing AFS clients, and is usually used with ka-forwarder.
.I fakeka
must run on the same host as your Kerberos V5 KDC, since it needs access
to the KDC database.  ka-forwarder should run on each of your AFS database
servers, pointing to your Kerberos V5 KDCs.
.I fakeka
should then be running on each of the KDCs, with the AFS database servers
listed as arguments to the
.B -f
option.
.PP
Note that principals you wish to use
.I fakeka
with must have either a V4-style key (des:v4) or an AFS-style key
(des:afs3).  V5 enctypes won't work.
.SH OPTIONS
.TP
\fB\-c\fP \fIcell\fP
The AFS cell for which
.I fakeka
will be handling requests.  If not given, this defaults to the same as the
Kerberos V5 realm (see
.B \-r
below).
.TP
.B \-d
Enables debugging.  When this flag is given,
.I fakeka
will run in the foreground and print debugging information to standard
error.  Overrides
.BR \-m .
.TP
\fB\-f\fP \fIforwarder\fP
Allows forwarded requests from
.IR forwarder ,
which is generally an AFS database server running ka-forwarder.  This
option can be given multiple times (up to 10).  Each system running
ka-forwarder should be specified with the
.B \-f
flag or forwarded requests from that host will not be answered.  (The
forwarders append their own address to the packet.
.TP
\fB\-l\fP \fIfacility\fP
Log actions via syslog with the given
.I facility
rather than the default of LOG_DAEMON.
.I facility
must be one of KERN, USER, MAIL, DAEMON, AUTH, LPR, NEWS, UUCP, CRON,
LOCAL0, LOCAL1, LOCAL2, LOCAL3, LOCAL4, LOCAL5, LOCAL6, or LOCAL7.  This
option is case-sensitive.  Not all of these facilities may be available,
depending on what pre-defined syslog facilities your system provides.
.TP
.B \-m
Fork and background when starting.  You will usually always want to give
this flag.
.TP
\fB\-p\fP \fIport\fP
Listen on the specified port rather than the default of 7004 (which is
what klog expects).
.I port
may be a number or a service name from
.IR /etc/services .
.TP
\fB\-r\fP \fIrealm\fP
The Kerberos V5 realm to which the requests are being translated.  The
default is the local default realm.
.SH EXAMPLES
Handle requests for a local cell whose name matches the local realm,
accepting forwarded queries from afs1.example.com and afs2.example.com:
.IP "" 4
fakeka -m -f afs1.example.com -f afs2.example.com
.PP
If the cell name doesn't match the realm name,
.B \-c
would need to be added, specifying the cell name.
.SH SEE ALSO
ka-forwarder(8)
