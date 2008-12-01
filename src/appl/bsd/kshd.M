.\" Copyright (c) 1983 Regents of the University of California.
.\" All rights reserved.  The Berkeley software License Agreement
.\" specifies the terms and conditions for redistribution.
.\"
.\"	@(#)rshd.8	6.3 (Berkeley) 5/24/86
.\"
.TH KRSHD 8
.SH NAME
kshd \- kerberized remote shell server
.SH SYNOPSIS
.B /usr/local/sbin/kshd 
[
.B \-kr45ec
]
[\fB\-D\fP \fIport\fP]
[\fB\-L\fP \fIvariable\fP]
.SH DESCRIPTION
.I Krshd
is the server for the 
.IR rcmd (3)
routine and, consequently, for the
.IR rsh (1)
program.  The server provides remote execution facilities
with authentication based on privileged port numbers from trusted hosts or 
the Kerberos authentication system.
.PP
The
.I kshd
server is invoked by \fIinetd(8c)\fP when it receives a connection
on the port indicated in /etc/inetd.conf.  A typical /etc/inetd.conf
configuration line for \fIkrshd\fP might be:

kshell	stream	tcp	nowait	root	/usr/local/sbin/kshd	kshd -5c

When a service request is received, the following protocol is initiated:

.IP 1) 
Authentication is checked
.IP 2)
Check authorization via the access-control files \fI.k5login\fP and
\fI.klogin\fP in the user's home directory.
.IP 3)
A null byte is returned on the initial socket
and the command line is passed to the normal login
shell of the user.  The
shell inherits the network connections established
by
.IR krshd .

\fIKrshd\fP can be configured  by command-line arguments passed
by \fIinetd(8)\fP.
 The options are:

.IP \fB\-5\fP 10
Allow Kerberos5 authentication with the \fI.k5login\fP access control file
to be trusted.  If this authentication system is used by the client and
the authorization check is passed, then the user is allowed to log in.  If
the user has no \fI.k5login\fP file, the login will be authorized if the
results of krb5_aname_to_localname conversion matches the account name.
Unless special rules are configured, this will be true if and only if the
Kerberos principal of the connecting user is in the default local realm
and the principal portion matches the account name.

.IP \fB\-4\fP 
Allow Kerberos4 authentication with the \fI.klogin\fP access control file
to be trusted.  If this authentication system is used by the client and the
authorization check is passed, then the user is allowed to log in.

.IP \fB\-k\fP 
Allow Kerberos5 and Kerberos4 as acceptable authentication
mechanisms.  This is the same as including \fB\-4\fP and \fB\-5\fP.

.IP \fB\-e\fP
Require the client to encrypt the connection.  Only Kerberos5 clients
support encryption.

.IP \fB\-L\ variable\fP
Carry through the current value of the specified variable into the
environment of the child.  This option can be used to preserve up to
four variables.


.IP \fB\-c\fP 
Require Kerberos5 clients to present a cryptographic
checksum of initial connection information like the name of the user
that the client is trying to access in the initial authenticator.
This checksum provides additionl security by preventing an attacker
from changing the initial connection information.  To benefit from
this security, only Kerberos5 should be trusted; Kerberos4 and rhosts
authentication do not include this checksum.  If this option is
specified, older Kerberos5 clients that do not send a checksum in the
authenticator will not be able to authenticate to this server.  This
option is mutually exclusive with the \fB-i\fP option.

	If neither the \fB-c\fP or \fB-i\fP options are specified,then
checksums are validated if presented.  Since it is difficult to remove
a checksum from an authenticator without making the authenticator
invalid, this default mode is almost as significant of a security
improvement as \fB-c\fP if new clients are used.  It has the additional
advantage of backwards compatability with some clients.
Unfortunately, clients before Kerberos V5, Beta5, generate invalid
checksums; if these clients are used, the \fB-i\fP option must be
used.

.IP \fB\-i\fP 
Ignore authenticator checksums if provided.  This option
ignore authenticator checksusm presented by current Kerberos clients
to protect initial connection information; it is the opposite of
\fB-c\fP.  This option is provided because some older
clients--particularly clients predating the release of Kerberos V5
Beta5 (May 1995)--present bogus checksums that prevent Kerberos
authentication from succeeding in the default mode.


.PP
\fIKrshd\fP supports six options which may be used for testing:

.IP \fB\-S\ keytab\fP 10
Set the \fIkeytab\fP file to use.

.IP \fB\-M\ realm\fP
Set the Kerberos realm to use.

.IP \fB\-A\fP
Don't allocate a reserved port for the stderr connection.

.IP \fB\-P\ path\fP
Use the argument to find the Kerberos binaries.  Normally a compiled
in argument is used.

.IP \fB\-D\ port\fP
Run in standalone mode, listening on \fBport\fP.  The daemon will exit
after one connection and will not background itself.

.TP
\fB\-w \fP[\fBip\fP|\fImaxhostlen\fP[\fB,\fP[\fBno\fP]\fBstriplocal\fP]]
Controls the form of the remote hostname passed to login(1).
Specifying \fBip\fP results in the numeric IP address always being
passed to login(1).  Specifying a number, \fImaxhostlen\fP, sets the
maximum length of the hostname passed to login(1) before it will be
passed as a numeric IP address.  If \fImaxhostlen\fP is 0, then the
system default, as determined by the utmp or utmpx structures, is
used.  The \fBnostriplocal\fP and \fBstriplocal\fP options, which must
be preceded by a comma, control whether or not the local host domain
is stripped from the remote hostname.  By default, the equivalent of
\fBstriplocal\fP is in effect.

.SH DIAGNOSTICS
Except for the last one listed below,
all diagnostic messages
are returned on the initial socket,
after which any network connections are closed.
An error is indicated by a leading byte with a value of
1 (0 is returned in step 3 above upon successful completion
of all the steps prior to the execution of the login shell).
.PP
.B ``locuser too long''
.br
The name of the user on the client's machine is
longer than 16 characters.
.PP
.B ``remuser too long''
.br
The name of the user on the remote machine is
longer than 16 characters.
.PP
.B ``command too long ''
.br
The command line passed exceeds the size of the argument
list (as configured into the system).
.PP
.B ``Login incorrect.''
.br
No password file entry for the user name existed.
.PP
.B ``No remote directory.''
.br
The 
.I chdir
command to the home directory failed.
.PP
.B ``Permission denied.''
.br
The authentication procedure described above failed.
.PP
.B ``Can't make pipe.''
.br
The pipe needed for the 
.BR stderr ,
wasn't created.
.PP
.B ``Try again.''
.br
A
.I fork
by the server failed.
.PP
.B ``<shellname>: ...''
.br
The user's login shell could not be started.  This message is returned
on the connection associated with the
.BR stderr ,
and is not preceded by a flag byte.
.SH SEE ALSO
rshd(8), rsh(1),
rcmd(3)
.SH BUGS
A facility to allow all data exchanges to be encrypted should be
present.
.PP
A more extensible protocol should be used.
