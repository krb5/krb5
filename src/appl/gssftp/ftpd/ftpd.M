.\" Copyright (c) 1985, 1988, 1991 The Regents of the University of California.
.\" All rights reserved.
.\"
.\" Redistribution and use in source and binary forms, with or without
.\" modification, are permitted provided that the following conditions
.\" are met:
.\" 1. Redistributions of source code must retain the above copyright
.\"    notice, this list of conditions and the following disclaimer.
.\" 2. Redistributions in binary form must reproduce the above copyright
.\"    notice, this list of conditions and the following disclaimer in the
.\"    documentation and/or other materials provided with the distribution.
.\" 3. All advertising materials mentioning features or use of this software
.\"    must display the following acknowledgement:
.\"	This product includes software developed by the University of
.\"	California, Berkeley and its contributors.
.\" 4. Neither the name of the University nor the names of its contributors
.\"    may be used to endorse or promote products derived from this software
.\"    without specific prior written permission.
.\"
.\" THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
.\" ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
.\" IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
.\" ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
.\" FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
.\" DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
.\" OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
.\" HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
.\" LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
.\" OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
.\" SUCH DAMAGE.
.\"
.\"     @(#)ftpd.8	6.9 (Berkeley) 3/16/91
.\" "
.TH FTPD 8
.SH NAME
ftpd \- DARPA Internet File Transfer Protocol server
.SH SYNOPSIS
.B ftpd
[\fB\-A \fP|\fB -a\fP] [\fB\-C\fP] [\fB\-c\fP] [\fB\-d\fP] [\fB-E\fP]
[\fB\-l\fP] [\fB\-v\fP] [\fB\-T\fP \fImaxtimeout\fP] [\fB\-t\fP \fItimeout\fP]
[\fB\-p\fP \fIport\fP] [\fB\-U\fP \fIftpusers-file\fP] [\fB\-u\fP \fIumask\fP]
[\fB\-r\fP \fIrealm-file\fP] [\fB\-s\fP \fIsrvtab\fP]
[\fB\-w\fP{\fBip\fP|\fImaxhostlen\fP[\fB,\fP{\fBstriplocal\fP|\fBnostriplocal\fP}]}]
.SH DESCRIPTION
.B Ftpd
is the
.SM DARPA
Internet File Transfer Protocol server process.  The server uses the
.SM TCP
protocol and listens at the port specified in the ``ftp'' service
specification; see
.IR services (5).
.PP
Available options:
.TP
.B \-A
Connections are only allowed for users who can authenticate via the
ftp AUTH mechanism. (Anonymous ftp may also be allowed if it is 
configured.) Ftpd will ask the user for a password if one is
required.
.TP
.B \-a
Connections are only allowed for users who can authenticate (via the
ftp AUTH mechanism) and who are authorized to connect to the named 
account without a password. (Anonymous ftp may also be allowed if it is 
configured.)
.TP
.B \-C
Non-anonymous users need local credentials (for example, to authenticate
to remote fileservers), and so they should be prompted for a password
unless they forwarded credentials as part of authentication.
.TP
.B \-c
Allow the CCC (Clear Command Channel) command to be used. This allows
less secure connections, and should probably only be used when debugging.
.TP
.B \-d
Debugging information is written to the syslog.  (Identical to -v)
.TP
.B \-E
Don't allow passwords to be typed across unencrypted connections.
.TP
.B \-l
Each
.IR ftp (1)
session is logged in the syslog.  If this flag appears twice, additional
information about operations performed (such as files retrieved, directories
created, etc.) will be logged via syslog.  If it appears three times, some
other statistics such as the number of bytes transferred will be logged via
syslog as well.
.TP
.B \-v
Debugging information is written to the syslog.  (Identical to -d)
.TP
\fB\-T\fP \fImaxtimeout\fP
A client may request a maximum timeout period allowed set to
.I timeout
seconds with the
.B \-T
option.  The default limit is 2 hours.  This is different from the normal
inactivity timeout specified by the
.B \-t
option (see below).
.TP
\fB\-t\fP \fItimeout\fP
The inactivity timeout period is set to
.I timeout
seconds (the default is 15 minutes).
.TP
\fB\-p\fP \fIport\fP
Run as a server and accept a connection on
.IR port .
Normally the ftp server is invoked by
.IR inetd (8).
.TP
\fB\-U\fP \fIftpusers-file\fP
Sets the full path and name of the
.I ftpusers
file to use.  The default value is normally
.IR /etc/ftpusers .
.TP
\fB\-u\fP \fIumask\fP
Sets the umask for the ftpd process.  The default value is normally 027.
.TP
\fB\-w \fP{\fBip\fP|\fImaxhostlen\fP[\fB,\fP{\fBstriplocal\fP|\fBnostriplocal\fP}]}
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
.PP
The ftp server currently supports the following ftp requests; case is
not distinguished.
.TP "\w'Request\ \ 'u"
.B Request
.B Description
.sp -1
.TP
ABOR
abort previous command
.sp -1
.TP
ACCT
specify account (ignored)
.sp -1
.TP
ADAT
send an authentication protocol message
.sp -1
.TP
ALLO
allocate storage (vacuously)
.sp -1
.TP
APPE
append to a file
.sp -1
.TP
AUTH
specify an authentication protocol to be performed
.sp -1
.TP
CCC
set the command channel protection mode to "Clear" (no protection).
Only available if the \fB-c\fP command-line option was given.
.sp -1
.TP
CDUP
change to parent of current working directory
.sp -1
.TP
CWD
change working directory
.sp -1
.TP
DELE
delete a file
.sp -1
.TP
ENC
send a privacy and integrity protected command (given in argument)
.sp -1
.TP
HELP
give help information
.sp -1
.TP
LIST
give list files in a directory (``ls -lgA'')
.sp -1
.TP
MIC
send an integrity protected command (given in argument)
.sp -1
.TP
MKD
make a directory
.sp -1
.TP
MDTM
show last modification time of file
.sp -1
.TP
MODE
specify data transfer
.I mode
.sp -1
.TP
NLST
give name list of files in directory
.sp -1
.TP
NOOP
do nothing
.sp -1
.TP
PASS
specify password
.sp -1
.TP
PASV
prepare for server-to-server transfer
.sp -1
.TP
PBSZ
specify a protection buffer size
.sp -1
.TP
PORT
specify data connection port
.sp -1
.TP
PROT
specify a protection level under which to protect data transfers
.sp -1
.TP
PWD
print the current working directory
.sp -1
.TP
QUIT
terminate session
.sp -1
.TP
REST
restart incomplete transfer
.sp -1
.TP
RETR
retrieve a file
.sp -1
.TP
RMD
remove a directory
.sp -1
.TP
RNFR
specify rename-from file name
.sp -1
.TP
RNTO
specify rename-to file name
.sp -1
.TP
SITE
non-standard commands (see next section)
.sp -1
.TP
SIZE
return size of file
.sp -1
.TP
STAT
return status of server
.sp -1
.TP
STOR
store a file
.sp -1
.TP
STOU
store a file with a unique name
.sp -1
.TP
STRU
specify data transfer
.I structure
.sp -1
.TP
SYST
show operating system type of server system
.sp -1
.TP
TYPE
specify data transfer
.I type
.sp -1
.TP
USER
specify user name
.sp -1
.TP
XCUP
change to parent of current working directory (deprecated)
.sp -1
.TP
XCWD
change working directory (deprecated)
.sp -1
.TP
XMKD
make a directory (deprecated)
.sp -1
.TP
XPWD
print the current working directory (deprecated)
.sp -1
.TP
XRMD
remove a directory (deprecated)
.PP
The following non-standard or
.SM UNIX
specific commands are supported by the SITE request.
.TP "\w'Request\ \ 'u"
.B Request
.B Description
.sp -1
.TP
UMASK
change umask. 
.IR E.g. ,
SITE UMASK 002
.sp -1
.TP
IDLE
set idle-timer. 
.IR E.g. ,
SITE IDLE 60
.sp -1
.TP
CHMOD
change mode of a file. 
.IR E.g. ,
SITE CHMOD 755 filename
.sp -1
.TP
HELP
give help information.
.IR E.g. ,
SITE HELP
.PP
The remaining ftp requests specified in Internet
.I RFC 959
are recognized, but not implemented.  MDTM and SIZE are not specified in
.I RFC
.IR 959 ,
but will appear in the next updated FTP RFC.
.PP
The ftp server will abort an active file transfer only when the ABOR
command is preceded by a Telnet "Interrupt Process" (IP) signal and a
Telnet "Synch" signal in the command Telnet stream, as described in
Internet
.I RFC
.IR 959 .
If a STAT command is received during a data transfer, preceded by a
Telnet IP and Synch, transfer status will be returned.
.PP
.B Ftpd
interprets file names according to the
``globbing''
conventions used by
.IR csh (1).
This allows users to utilize the metacharacters ``\&*?[]{}~''.
.PP
.B Ftpd
authenticates users according to the following rules:
.sp
.TP
  1.
The user name must be in the password data base,
.IR /etc/passwd .
.TP
  2.
An
.SM AUTH
command must be accepted, the ensuing authentication protocol (conducted
via
.SM ADAT
commands and replies) must successfully complete, and the authenticated
user must permitted access.  Otherwise, a valid password which is not
null must be provided by the client.
.TP
  3.
The user name must not appear in the file
.IR /etc/ftpusers .
.TP
  4.
The user must have a standard shell returned by 
.IR getusershell (3).
.TP
  5.
If the user name is ``anonymous'' or ``ftp'', an anonymous ftp account
must be present in the password file (user ``ftp'').  In this case the
user is allowed to log in by specifying any password (by convention this
is given as the client host's name).
.PP
In the last case,
.B ftpd
takes special measures to restrict the client's access privileges.  The
server performs a
.IR chroot (2)
command to the home directory of the ``ftp'' user.  In order that system
security is not breached, it is recommended that the ``ftp'' subtree be
constructed with care; the following rules are recommended.
.TP
.I ~ftp
Make the home directory owned by ``ftp'' and unwritable by anyone.
.TP
.I ~ftp/bin
Make this directory owned by the super-user and unwritable by anyone.
The program
.IR ls (1)
must be present to support the list command.  This program should have
mode 111.
.TP
.I ~ftp/etc
Make this directory owned by the super-user and unwritable by anyone.
The files
.IR passwd (5)
and
.IR group (5)
must be present for the
.I ls
command to be able to produce owner names rather than numbers.  The
password field in
.I passwd
is not used, and should not contain real encrypted passwords.  These
files should be mode 444.
.TP
.I ~ftp/pub
Make this directory mode 777 and owned by ``ftp''.  Users should then
place files which are to be accessible via the anonymous account in this
directory.
.PP
If an
.SM ADAT
command succeeds, the control channel must be either integrity or
privacy protected.  In this case, the
.SM MIC
and
.SM ENC
commands are the only commands allowed over the control channel.  The
argument to the
.SM MIC
command is a base 64 encoded string which, when decoded, is an ftp
command integrity protected with a cryptographic checksum.  The argument
to the
.SM ENC
command is a base 64 encoded string which, when decoded, is an ftp
command privacy and integrity protected with encryption.
.PP
If an
.SM ADAT
command succeeds, ftp replies will also be either integrity or privacy
protected.
.PP
If an
.SM ADAT
command succeeds, the data channel can also be integrity or privacy
protected.  The
.SM PROT
command accepts S for integrity and P for privacy protection.  Unless an
.SM ADAT
command succeeds, the only protection level accepted by the
.SM PROT
command is C (clear).
.SH SEE ALSO
.IR ftp (1),
.IR getusershell (3),
.IR syslogd (8)
.PP
Lunt, S. J., FTP Security Extensions, Internet Draft, November 1993.
.SH BUGS
The anonymous account is inherently dangerous and should avoided when
possible.
.PP
The server must run as the super-user to create sockets with privileged
port numbers.  It maintains an effective user id of the logged in user,
reverting to the super-user only when binding addresses to sockets.  The
possible security holes have been extensively scrutinized, but are
possibly incomplete.
.SH HISTORY
The
.B ftpd
command appeared in 4.2BSD.
