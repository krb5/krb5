.\" Copyright (c) 1983 Regents of the University of California.
.\" All rights reserved.  The Berkeley software License Agreement
.\" specifies the terms and conditions for redistribution.
.\"
.\"	@(#)rlogind.8c	6.3 (Berkeley) 5/24/86
.\"
.TH KRLOGIND 8C "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
krlogind \- remote login server
.SH SYNOPSIS
.B /etc/rlogind
[
.B \-kKrRpPex
]
.SH DESCRIPTION
.I Krlogind
is the server for the 
.IR rlogin (1C)
program.  The server is 
based on rlogind(8C) but uses kerberos authentication.
.PP
The 
.I krlogind
server is invoked by \fIinetd(8c)\fP when it receives a
connection on the port indicated in /etc/inetd.conf.  A typical
/etc/inetd.conf configuration line for \fIkrlogind\fP might be:

klogin	stream	tcp	nowait	root	/krb5/sbin/krlogind krlogind -K

When a service request is received, the follow protocol is initiated:

.IP 1)
Check authentication.
.IP 2)
Check authorization via the access-control files \fI.k5login\fP 
and \fI.rhosts\fP in the user's home directory.
.IP 3)
Prompt for password if any checks fail.
.PP
If the authentication succeeds, login the user by calling the accompanying 
login.krb5 or /bin/login, according to the definition of 
DO_NOT_USE_K_LOGIN.  
.PP 
The configuration of \fIkrlogind\fP is done
either by command-line arguments passed by
inetd, or by the name of the daemon. If command-line arguments are
present, they  take priority. The options are:
.IP \fB\-k\fP 10
Check authorization in ~/.k5login.

.IP \fB\-K\fP
Similar to \fb\-k\fP except that the authorization check must succeed
inorder for the login to succeed.

.IP \fB\-r\fP 
Check authorization in ~/.rhosts.

.IP \fB\-K\fP
Similar to \fb\-r\fP except that the authorization check must succeed
inorder for the login to succeed.

.IP \fB\-p\fP 
Prompt the user for a password.  If \fB-r\fP or \fB-k\fP
is passed \fB-p\fP is necessary to allow password authentication.
Otherwise, if all previous checks fail, login permission is denied

.IP \fB\-P\fP
Prompt the user for a password.  If the -P option is passed, then the
password is verified in addition to all other checks.
.IP \fB\-e\fP
Create an encrypted session.
.IP \fB\-x\fP
Create an encrypted session.
.PP
If no command-line arguments are present, then the presence of the 
letters kKrRpPex in the program-name before "logind" determine the 
behaviour of the program exactly as with the command-line arguments.
.PP
If the ~/.rhosts check is to be used, then the program verifies that
the client is connecting
from a privileged port, before allowing login.
.PP
The parent of the login process manipulates the master side of
the pseduo terminal, operating as an intermediary
between the login process and the client instance of the
.I rlogin(1C)
program.  In normal operation, the packet protocol described
in
.IR pty (4)
is invoked to provide ^S/^Q type facilities and propagate
interrupt signals to the remote programs.  The login process
propagates the client terminal's baud rate and terminal type,
as found in the environment variable, ``TERM''; see
.IR environ (7).
The screen or window size of the terminal is requested from the client,
and window size changes from the client are propagated to the pseudo terminal.
.PP
.I Krlogind
supports three options which are used for testing purposes:

.IP \fB\-S\ srvtab\fP 10
Set the \fIsrvtab\fP file to use.

.IP \fB\-M\ realm\fP
Set the Kerberos realm to use.

.IP \fB\-L\ login\fP
Set the login program to use.  This option only has an effect if
DO_NOT_USE_K_LOGIN was not defined when
.I krlogind
was compiled.
.SH DIAGNOSTICS
All diagnostic messages are returned on the connection
associated with the
.BR stderr ,
after which any network connections are closed.
An error is indicated by a leading byte with a value of 1.
.PP
.B ``Try again.''
.br
A
.I fork
by the server failed.
.PP
.B ``/bin/sh: ...''
.br
The user's login shell could not be started.
.SH SEE ALSO
rlogind(8C), rlogin(1C)
.SH BUGS
A more extensible protocol should be used.
