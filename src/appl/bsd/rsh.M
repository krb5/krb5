.\" appl/bsd/rsh.M
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
.\"	@(#)rsh.1	6.2 (Berkeley) 9/20/88
.\" "
.TH RSH 1
.SH NAME
rsh \- remote shell
.SH SYNOPSIS
.B rsh
.I host
[\fB\-l\fP \fIusername\fP] [\fB\-n\fP] [\fB\-d\fP] [\fB\-k\fP
\fIrealm\fP] [\fB\-f\fP | \fB\-F\fP] [\fB\-x\fP]
[\fB\-PN | \-PO\fP]
.I command
.SH DESCRIPTION
.B Rsh
connects to the specified
.I host,
and executes the specified \fIcommand\fR.
.B Rsh
copies its standard input to the remote command, the standard output of
the remote command to its standard output, and the standard error of the
remote command to its standard error.  This implementation of
.B rsh
will accept any port for the standard error stream.  Interrupt, quit and
terminate signals are propagated to the remote command; \fIrsh\fP
normally terminates when the remote command does.
.PP
Each user may have a private authorization list in a file \&.k5login in
his login directory.  Each line in this file should contain a Kerberos
principal name of the form
.IR principal/instance@realm .
If there is a ~/.k5login file, then access is granted to the account if
and only if the originater user is authenticated to one of the
princiapls named in the ~/.k5login file.  Otherwise, the originating
user will be granted access to the account if and only if the
authenticated principal name of the user can be mapped to the local
account name using the aname -> lname mapping rules (see
.IR krb5_anadd (8)
for more details).
.SH OPTIONS
.TP
\fB\-l\fP \fIusername\fP
sets the remote username to
.IR username .
Otherwise, the remote username will be the same as the local username.
.TP
\fB\-x\fP
causes the network session traffic to be encrypted.  This applies only
to the input and output streams, and not the command line.
.TP
\fB\-f\fP
cause nonforwardable Kerberos credentials to be forwarded to the remote
machine for use by the specified
.IR command .
They will be removed when
.I command
finishes.  This option is mutually exclusive with the
.B \-F
option.
.TP
\fB\-F\fP
cause
.I forwardable
Kerberos credentials to be forwarded to the remote machine for use by
the specified
.IR command .
They will be removed when
.I command
finishes.  This option is mutually exclusive with the
.B \-f
option.
.TP
\fB\-k\fP \fIrealm\fP
causes 
.I rsh
to obtain tickets for the remote host in
.I realm
instead of the remote host's realm as determined by
.IR krb_realmofhost (3).
.TP
.B \-d
turns on socket debugging (via
.IR setsockopt (2))
on the TCP sockets used for communication with the remote host.
.TP
.B \-n
redirects input from the special device
.I /dev/null
(see the BUGS section below).
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
.PP
If you omit
.IR command ,
then instead of executing a single command, you will be logged in on the
remote host using
.IR rlogin (1).
.PP
Shell metacharacters which are not quoted are interpreted on the local
machine, while quoted metacharacters are interpreted on the remote
machine.  Thus the command
.PP
\ \ \ rsh otherhost cat remotefile >> localfile
.PP
appends the remote file
.I remotefile
to the local file
.IR localfile ,
while
.PP
\ \ \ rsh otherhost cat remotefile ">>" otherremotefile
.PP
appends
.I remotefile
to
.IR otherremotefile .
.SH FILES
.TP "\w'~/.k5login\ \ 'u"
/etc/hosts
.sp -1v
.TP
~/\&.k5login
(on remote host) - file containing Kerberos principals that are allowed
access.
.SH SEE ALSO
rlogin(1), kerberos(3), krb_sendauth(3), krb_realmofhost(3), kshd(8)
.SH BUGS
If you are using
.IR csh (1)
and put a
.IR rsh (1)
in the background without redirecting its input away from the terminal,
it will block even if no reads are posted by the remote command.  If no
input is desired you should redirect the input of
.I rsh
to /dev/null using the
.B \-n
option.
.PP
You cannot run an interactive command (like
.IR rogue (6)
or
.IR vi (1));
use
.IR rlogin (1).
.PP
Stop signals stop the local \fIrsh\fP process only; this is arguably
wrong, but currently hard to fix for reasons too complicated to explain
here.
