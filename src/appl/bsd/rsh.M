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
.\"
.TH RSH 1 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
rsh \- remote shell
.SH SYNOPSIS
.B rsh
host
[
.B \-l
username
] [
.B \-n
] [
.B \-d
] [
.B \-k
realm ] [
.B \-A
] command
.br
host
[
.B \-l
username
] [
.B \-n
] [
.B \-d
] [
.B \-k
realm ] [
.B \-A
] command
.SH DESCRIPTION
.I Rsh
connects to the specified
.I host,
and executes the specified \fIcommand\fR.
.I Rsh
copies its standard input to the remote command, the standard
output of the remote command to its standard output, and the
standard error of the remote command to its standard error.
Interrupt, quit and terminate signals are propagated to the remote
command; \fIrsh\fP normally terminates when the remote command does.
.PP
The remote username used is the same as your local username,
unless you specify a different remote name with the
.B \-l
option.
.PP
Each user may have a private authorization list in a file \&.k5login
in his login directory.  Each line in this file should contain a
Kerberos principal name of the form 
.IR principal/instance@realm .
If there is a ~/.k5login file, then access is granted to the account if
and only if the originater user is authenticated to one of the
princiapls named in the ~/.k5login file.  Otherwise, the originating
user will be granted access to the account if and only if the
authenticated principal name of the user can be mapped to the local
account name using the aname -> lname mapping rules (see \fIkrb5_anadd(8)\fP
for more details).
.PP
The
.B \-k
\fIrealm\fP option causes 
.I rsh
to obtain tickets for the remote host in
.I realm
instead of the remote host's realm as determined by
.IR krb_realmofhost (3).
.PP
The
.B \-d
option turns on socket debugging (via \fIsetsockopt(2)\fR) on the TCP
sockets used for communication with the remote host.
.PP
The
.B \-n
option redirects input from the special device
.I /dev/null
(see the BUGS section below).
.PP
The
.B \-A
option accepts any port number for the stderr stream.  Normally
.I rsh
requires a reserved port number.  This option is used for debugging.
.PP
If you omit
.I command,
then instead of executing a single command, you will be logged in
on the remote host using
.IR rlogin (1).
.PP
Shell metacharacters which are not quoted are interpreted
on local machine, while quoted metacharacters are interpreted on
the remote machine.
Thus the command
.PP
\ \ \ rsh otherhost cat remotefile >> localfile
.PP
appends the remote file
.I remotefile
to the local file
.I localfile,
while
.PP
\ \ \ rsh otherhost cat remotefile ">>" otherremotefile
.PP
appends
.I remotefile
to
.I otherremotefile.
.PP
The host names for local machines are also commands in the directory
/usr/hosts; if you put this directory in your search path
then the
.B rsh
on the command line can be omitted.
.SH FILES
.ta 2i
/etc/hosts
.br
/usr/hosts/*
.br
\&.k5login		in the user's home directory
.DT
.SH SEE ALSO
rlogin(1), kerberos(3), krb_sendauth(3), krb_realmofhost(3)
.SH BUGS
If you are using
.IR csh (1)
and put a
.IR rsh (1)
in the background without redirecting its input
away from the terminal, it will block even if no reads
are posted by the remote command.  If no input is desired
you should redirect the input of
.I rsh
to /dev/null using the
.B \-n
option.
.PP
You cannot run an interactive command
(like
.IR rogue (6)
or
.IR vi (1));
use
.IR rlogin (1).
.PP
Stop signals stop the local \fIrsh\fP process only; this is arguably
wrong, but currently hard to fix for reasons too complicated to
explain here.
