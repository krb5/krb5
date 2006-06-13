.\" appl/bsd/rlogin.M
.\"
.\" Copyright (c) 1983 The Regents of the University of California.
.\" All rights reserved.
.\"
.\" Redistribution and use in source and binary forms are permitted
.\" provided that the above copyright notice and this paragraph are
.\" duplicated in all such forms and that any documentation,
.\" advertising materials, and other materials related to such
.\" distribution and use acknowledge that the software was developed
.\" by the University of California, Berkeley.  The name of the
.\" University may not be used to endorse or promote products derived
.\" from this software without specific prior written permission.
.\" THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
.\" IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
.\" WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
.\"
.\"	@(#)rlogin.1	6.9 (Berkeley) 9/19/88
.\" "
.TH RLOGIN 1
.SH NAME
rlogin \- remote login
.SH SYNOPSIS
.B rlogin
.I rhost
[\fB\-e\fP\fI\|c\fP] [\fB\-8\fP] [\fB\-c\fP] [ \fB\-a\fP] [\fB\-f\fP]
[\fB\-F\fP] [\fB\-t\fP \fItermtype\fP] [\fB\-n\fP] [\fB\-7\fP]
[\fB\-PN | \-PO\fP] [\fB\-4\fP]
[\fB\-d\fP] [\fB\-k\fP \fIrealm\fP] [\fB\-x\fP] [\fB\-L\fP] [\fB\-l\fP
\fIusername\fP]
.PP
.SH DESCRIPTION
.I Rlogin
connects your terminal on the current local host system
.I lhost
to the remote host system
.I rhost.
.PP
The version built to use Kerberos authentication is very similar to the
standard Berkeley rlogin(1), except that instead of the \fIrhosts\fP
mechanism, it uses Kerberos authentication to determine the
authorization to use a remote account.
.PP
Each user may have a private authorization list in a file \&.k5login in
his login directory.  Each line in this file should contain a Kerberos
principal name of the form
.IR principal/instance@realm .
If the originating user is authenticated to one of the principals named
in \&.k5login, access is granted to the account.  If there is no
/.k5login file, the principal will be granted access to the account
according to the aname\->lname mapping rules.  (See
.IR krb5_anadd(8) 
for more details.)  Otherwise a login and password will be prompted for
on the remote machine as in
.IR login (1).
To avoid some security problems, the \&.k5login file must be owned by
the remote user.
.PP
If there is some problem in marshaling the Kerberos authentication
information, an error message is printed and the standard UCB rlogin is
executed in place of the Kerberos rlogin.
.PP
A line of the form ``~.'' disconnects from the remote host, where ``~''
is the escape character.  Similarly, the line ``~^Z'' (where ^Z,
control-Z, is the suspend character) will suspend the rlogin session.
Substitution of the delayed-suspend character (normally ^Y) for the
suspend character suspends the send portion of the rlogin, but allows
output from the remote system.
.PP
The remote terminal type is the same as your local terminal type (as
given in your environment TERM variable), unless the
.B \-t
option is specified (see below).  The terminal or window size is also
copied to the remote system if the server supports the option, and
changes in size are reflected as well.
.PP
All echoing takes place at the remote site, so that (except for delays)
the rlogin is transparent.  Flow control via ^S and ^Q and flushing of
input and output on interrupts are handled properly.
.SH OPTIONS
.TP
.B \-8
allows an eight-bit input data path at all times; otherwise parity bits
are stripped except when the remote side's stop and start characters are
other than ^S/^Q.  Eight-bit mode is the default.
.TP
.B \-L
allows the rlogin session to be run in litout mode.
.TP
\fB\-e\fP\fIc\fP
sets the escape character to
.IR c .
There is no space separating this option flag and the new escape
character.
.TP
.B \-c
require confirmation before disconnecting via ``~.''
.TP
.B \-a
force the remote machine to ask for a password by sending a null local
username.  This option has no effect unless the standard UCB rlogin is
executed in place of the Kerberos rlogin (see above).
.TP
\fB\-f\fP
forward a copy of the local credentials to the remote system.
.TP
\fB\-F\fP
forward a
.I forwardable
copy of the local credentials to the remote system.
.TP
\fB\-t\fP \fItermtype\fP
replace the terminal type passed to the remote host with
.IR termtype .
.TP
.B \-n
prevent suspension of rlogin via ``~^Z'' or ``~^Y''.
.TP
.B \-7
force seven-bit transmissions.
.TP
.B \-d
turn on socket debugging (via
.IR setsockopt (2))
on the TCP sockets used for communication with the remote host.
.TP
.B \-k
request rlogin to obtain tickets for the remote host in realm
.I realm
instead of the remote host's realm as determined by 
.IR krb_realmofhost (3).
.TP
\fB\-x\fP
turn on DES encryption for data passed via the rlogin session.  This
applies only to input and output streams, so the username is sent
unencrypted.  This significantly reduces response time and
significantly increases CPU utilization.
.TP
\fB-PN\fP
.TP
\fB-PO\fP
Explicitly request new or old version of the Kerberos ``rcmd''
protocol.  The new protocol avoids many security problems found in the
old one, but is not interoperable with older servers.  (An
"input/output error" and a closed connection is the most likely result
of attempting this combination.)  If neither option is specified, some
simple heuristics are used to guess which to try.
.TP
\fB\-4\fP
Use Kerberos V4 authentication only; don't try Kerberos V5.
.SH SEE ALSO
rsh(1), kerberos(1), krb_sendauth(3), krb_realmofhost(3), rlogin(1) [UCB
version], klogind(8)
.SH FILES
.TP "\w'~/\&.k5login\ \ 'u"
~/\&.k5login
(on remote host) - file containing Kerberos principals that are allowed
access.
.SH BUGS
More of the environment should be propagated.
