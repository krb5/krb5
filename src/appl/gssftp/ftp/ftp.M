.\" Copyright (c) 1985, 1989, 1990 The Regents of the University of California.
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
.\"	@(#)ftp.1	6.18 (Berkeley) 7/30/91
.\" "
.TH FTP 1
.SH NAME
ftp \- ARPANET file transfer program
.SH SYNOPSIS
.B ftp
[\fB\-v\fP] [\fB\-d\fP] [\fB\-i\fP] [\fB\-n\fP] [\fB\-g\fP] [\fB\-k\fP
\fIrealm\fP] [\fB\-f\fP] [\fB\-x\fP] [\fB\-u\fP] [\fB\-t\fP] [\fIhost\fP]
.SH DESCRIPTION
.B FTP
is the user interface to the
.SM ARPANET
standard File Transfer Protocol.  The program allows a user to transfer
files to and from a remote network site.
.SH OPTIONS
Options may be specified at the command line, or to the command
interpreter.
.TP
.B \-v
Verbose option forces
.B ftp
to show all responses from the remote server, as well as report on data
transfer statistics.
.TP
.B \-n
Restrains
.B ftp
from attempting ``auto-login'' upon initial connection.  If auto-login
is enabled,
.B ftp
will check the
.I .netrc
(see below) file in the user's home directory for an entry describing an
account on the remote machine.  If no entry exists,
.B ftp
will prompt for the remote machine login name (default is the user
identity on the local machine), and, if necessary, prompt for a password
and an account with which to login.
.TP
.B \-u
Restrains
.B ftp
from attempting ``auto-authentication'' upon initial connection.  If
auto-authentication is enabled,
.B ftp
attempts to authenticate to the
.SM FTP
server by sending the
.SM AUTH
command, using whichever authentication types are locally supported.
Once an authentication type is accepted, an authentication protocol
will proceed by issuing
.SM ADAT
commands.  This option also disables auto-login.
.TP
.B \-i
Turns off interactive prompting during multiple file transfers.
.TP
.B \-d
Enables debugging.
.TP
.B \-g
Disables file name globbing.
.TP
.B \-f
Causes credentials to be forwarded to the remote host.
.TP
.B \-x
Causes the client to attempt to negotiate encryption (data and command
protection levels ``private'') immediately after successfully
authenticating.
.TP
.B \-t
Enables packet tracing.
.SH COMMANDS
The client host with which
.B ftp
is to communicate may be specified on the command line.  If this is
done,
.B ftp
will immediately attempt to establish a connection to an
.SM FTP
server on that host; otherwise,
.B ftp
will enter its command interpreter and await instructions from the user.
When
.B ftp
is awaiting commands from the user the prompt
``ftp>''
is provided to the user.  The following commands are recognized by
.BR ftp :
.TP
\fB\&!\fP [\fIcommand\fP] [\fIargs\fP]]
Invoke an interactive shell on the local machine.  If there are
arguments, the first is taken to be a command to execute directly, with
the rest of the arguments as its arguments.
.TP
\fB\&$\fP \fImacro-name\fP [\fIargs\fP]
Execute the macro
.I macro-name
that was defined with the
.B macdef
command.  Arguments are passed to the macro unglobbed.
.TP
\fBaccount\fP [\fIpasswd\fP]
Supply a supplemental password required by a remote system for access to
resources once a login has been successfully completed.  If no argument
is included, the user will be prompted for an account password in a
non-echoing input mode.
.TP
\fBappend\fP \fIlocal-file\fP [\fIremote-file\fP]
Append a local file to a file on the remote machine.  If
.I remote-file
is left unspecified, the local file name is used in naming the remote
file after being altered by any
.B ntrans
or
.B nmap
setting.  File transfer uses the current settings for
.BR type ,
.BR format ,
.BR mode ,
and
.BR structure .
.TP
.B ascii
Set the file transfer
.B type
to network
.SM ASCII .
This is the default type.
.TP
.B bell
Arrange that a bell be sounded after each file transfer command is
completed.
.TP
.B binary
Set the file transfer
.B type
to support binary file transfer.
.TP
.B bye
Terminate the
.SM FTP
session with the remote server and exit
.BR ftp .
An end of file will also terminate the session and exit.
.TP
.B case
Toggle remote computer file name case mapping during
.B mget
commands.  When
.B case
is on (default is off), remote computer file names with all letters in
upper case are written in the local directory with the letters mapped to
lower case.
.TP
.B ccc
Turn off integrity protection on the command channel.  This command
must be sent integrity protected, and must be proceeded by a successful
.SM ADAT
command.  Since turning off integrity protection potentially
allows an attacker to insert commands onto the command channel, some
.SM FTP
servers may refuse to honor this command.
.TP
\fBcd\fP \fIremote-directory\fP
Change the working directory on the remote machine to
.IR remote-directory .
.TP
.B cdup
Change the remote machine working directory to the parent of the current
remote machine working directory.
.TP
\fBchmod\fP \fImode\fP \fIfile-name\fP
Change the permission modes of the file
.I file-name
on the remote system to
.IR mode .
.TP
.B clear
Set the protection level on data transfers to ``clear''.  If no
.SM ADAT
command succeeded, then this is the default protection level.
.TP
.B close
Terminate the
.SM FTP
session with the remote server, and return to the command interpreter.
Any defined macros are erased.
.TP
\fBcprotect\fP [\fIprotection-level\fP]
Set the protection level on commands to
.IR protection-level .
The valid protection levels are ``clear'' for unprotected commands,
``safe'' for commands integrity protected by
cryptographic checksum, and ``private'' for commands
confidentiality and integrity protected by encryption.  If an
.SM ADAT
command succeeded, then the default command protection level is
``safe'', otherwise the only possible level is ``clear''.  If no
level is specified, the current level is printed.
.B cprotect clear
is equivalent to the
.B ccc
command.
.TP
.B cr
Toggle carriage return stripping during ascii type file retrieval.
Records are denoted by a carriage return/linefeed sequence during ascii
type file transfer.  When
.B cr
is on (the default), carriage returns are stripped from this sequence to
conform with the
.SM UNIX
single linefeed record delimiter.  Records on non-UNIX remote systems
may contain single linefeeds; when an ascii type transfer is made, these
linefeeds may be distinguished from a record delimiter only when
.B cr
is off.
.TP
\fBdelete\fP \fIremote-file\fP
Delete the file
.I remote-file
on the remote machine.
.TP
\fBdebug\fP [\fIdebug-value\fP]
Toggle debugging mode.  If an optional
.I debug-value
is specified it is used to set the debugging level.  When debugging is
on,
.B ftp
prints each command sent to the remote machine, preceded by the string
`\-\->'
.TP
\fBdir\fP [\fIremote-directory\fP] [\fIlocal-file\fP]
Print a listing of the directory contents in the directory,
.IR remote-directory ,
and, optionally, placing the output in
.IR local-file .
If interactive prompting is on,
.B ftp
will prompt the user to verify that the last argument is indeed the
target local file for receiving
.B dir
output.  If no directory is specified, the current working directory on
the remote machine is used.  If no local file is specified, or
.I local-file
is
`\fB\-\fP',
output comes to the terminal.
.TP
.B disconnect
A synonym for
.IR close .
.TP
\fBform\fP \fIformat\fP
Set the file transfer
.B form
to
.IR format .
The default format is ``file''.
.TP
\fBget\fP \fIremote-file\fP [\fIlocal-file\fP]
Retrieve the file
.I remote-file
and store it on the local machine.  If the local file name is not
specified, it is given the same name it has on the remote machine,
subject to alteration by the current
.BR case ,
.BR ntrans ,
and
.B nmap
settings.  The current settings for
.BR type ,
.BR form ,
.BR mode ,
and
.B structure
are used while transferring the file.
.TP
.B glob
Toggle filename expansion for
.BR mdelete ,
.BR mget ,
and
.BR mput .
If globbing is turned off with
.BR glob ,
the file name arguments are taken literally and not expanded.  Globbing
for
.B mput
is done as in
.IR csh (1).
For
.B mdelete
and
.BR mget ,
each remote file name is expanded separately on the remote machine and
the lists are not merged.  Expansion of a directory name is likely to be
different from expansion of the name of an ordinary file: the exact
result depends on the foreign operating system and ftp server, and can
be previewed by doing
`mls remote-files \-'
Note:
.B mget
and
.B mput
are not meant to transfer entire directory subtrees of files.  That can
be done by transferring a
.IR tar (1)
archive of the subtree (in binary mode).
.TP
.B hash
Toggle hash-sign (``#'') printing for each data block transferred.  The
size of a data block is 1024 bytes.
.TP
\fBhelp\fP [\fIcommand\fP]
Print an informative message about the meaning of
.IR command .
If no argument is given,
.B ftp
prints a list of the known commands.
.TP
\fBidle\fP [\fIseconds\fP]
Set the inactivity timer on the remote server to
.I seconds
seconds.  If
.I seconds
is omitted, the current inactivity timer is printed.
.TP
\fBlcd\fP [\fIdirectory\fP]
Change the working directory on the local machine.  If no
.I directory
is specified, the user's home directory is used.
.TP
\fBls\fP [\fIremote-directory\fP] [\fIlocal-file\fP]
Print a listing of the contents of a directory on the remote machine.
The listing includes any system-dependent information that the server
chooses to include; for example, most
.SM UNIX
systems will produce output from the command `ls \-l'.  (See also
.BR nlist .)
If
.I remote-directory
is left unspecified, the current working directory is used.  If
interactive prompting is on,
.B ftp
will prompt the user to verify that the last argument is indeed the
target local file for receiving
.B ls
output.  If no local file is specified, or if
.I local-file
is
`\fB\-\fP',
the output is sent to the terminal.
.TP
\fBmacdef\fP\fImacro-name\fP
Define a macro.  Subsequent lines are stored as the macro
.IR macro-name ;
a null line (consecutive newline characters in a file or carriage
returns from the terminal) terminates macro input mode.  There is a
limit of 16 macros and 4096 total characters in all defined macros.
Macros remain defined until a
.B close
command is executed.  The macro processor interprets `$' and `\e' as
special characters.  A `$' followed by a number (or numbers) is replaced
by the corresponding argument on the macro invocation command line.  A
`$' followed by an `i' signals that macro processor that the executing
macro is to be looped.  On the first pass `$i' is replaced by the first
argument on the macro invocation command line, on the second pass it is
replaced by the second argument, and so on.  A `\e' followed by any
character is replaced by that character.  Use the `\e' to prevent
special treatment of the `$'.
.TP
\fBmdelete\fP [\fIremote-files\fP]
Delete
.I remote-files
on the remote machine.
.TP
\fBmdir\fP \fIremote-files\fP \fIlocal-file\fP
Like
.BR dir ,
except multiple remote files may be specified.  If interactive prompting
is on,
.B ftp
will prompt the user to verify that the last argument is indeed the
target local file for receiving
.B mdir
output.
.TP
\fBmget\fP \fIremote-files\fP
Expand the
.I remote-files
on the remote machine and do a
.B get
for each file name thus produced.  See
.B glob
for details on the filename expansion.  Resulting file names will then
be processed according to
.BR case ,
.BR ntrans ,
and
.B nmap
settings.  Files are transferred into the local working directory, which
can be changed with `lcd directory'; new local directories can be
created with
`\&! mkdir directory'.
.TP
\fBmkdir\fP \fIdirectory-name\fP
Make a directory on the remote machine.
.TP
\fBmls\fP \fIremote-files\fP \fIlocal-file\fP
Like
.BR nlist ,
except multiple remote files may be specified, and the
.I local-file
must be specified.  If interactive prompting is on,
.B ftp
will prompt the user to verify that the last argument is indeed the
target local file for receiving
.B mls
output.
.TP
\fBmode\fP [\fImode-name\fP]
Set the file transfer
.B mode
to
.IR mode-name .
The default mode is ``stream'' mode.
.TP
\fBmodtime\fP \fIfile-name\fP
Show the last modification time of the file on the remote machine.
.TP
\fBmput\fP \fIlocal-files\fP
Expand wild cards in the list of local files given as arguments and do a
.B put
for each file in the resulting list.  See
.B glob
for details of filename expansion.  Resulting file names will then be
processed according to
.B ntrans
and
.B nmap
settings.
.TP
\fBnewer\fP \fIfile-name\fP
Get the file only if the modification time of the remote file is more
recent that the file on the current system.  If the file does not exist
on the current system, the remote file is considered
.BR newer .
Otherwise, this command is identical to
.BR get .
.TP
\fBnlist\fP [\fIremote-directory\fP] [\fIlocal-file\fP]
Print a list of the files in a directory on the remote machine.  If
.I remote-directory
is left unspecified, the current working directory is used.  If
interactive prompting is on,
.B ftp
will prompt the user to verify that the last argument is indeed the
target local file for receiving
.B nlist
output.  If no local file is specified, or if
.I local-file
is `\fB\-\fP', the output is sent to the terminal.
.TP
\fBnmap\fP [\fIinpattern\fP \fIoutpattern\fP]
Set or unset the filename mapping mechanism.  If no arguments are
specified, the filename mapping mechanism is unset.  If arguments are
specified, remote filenames are mapped during
.B mput
commands and
.B put
commands issued without a specified remote target filename.
If arguments are specified, local filenames are mapped during
.B mget
commands and
.B get
commands issued without a specified local target filename.  This command
is useful when connecting to non\-UNIX remote computer with different
file naming conventions or practices.  The mapping follows the pattern
set by
.I inpattern
and
.IR outpattern .
[\fIInpattern\fP] is a template for incoming filenames (which may have
already been processed according to the
.B ntrans
and
.B case
settings).  Variable templating is accomplished by including the
sequences `$1', `$2', ..., `$9' in
.IR inpattern .
Use `\e' to prevent this special treatment of the `$' character.  All
other characters are treated literally, and are used to determine the
.B nmap
[\fIinpattern\fP] variable values.  For example, given
.I inpattern
$1.$2 and the remote file name "mydata.data", $1 would have the value
"mydata", and $2 would have the value "data".  The
.I outpattern
determines the resulting mapped filename.  The sequences `$1', `$2',
\&..., `$9' are replaced by any value resulting from the
.I inpattern
template.  The sequence `$0' is replace by the original filename.
Additionally, the sequence `[\fIseq1\fP, \fIseq2\fP]' is replaced by
[\fIseq1\fP] if
.I seq1
is not a null string; otherwise it is replaced by
.IR seq2 .
For example, the command
.sp
.nf
	nmap $1.$2.$3 [$1,$2].[$2,file]
.fi
.sp
would yield the output filename "myfile.data" for input filenames
"myfile.data" and "myfile.data.old", "myfile.file" for the input
filename "myfile", and "myfile.myfile" for the input filename ".myfile".
Spaces may be included in
.IR outpattern ,
as in the example: `nmap $1 sed "s/ *$//" > $1'.  Use the `\e' character
to prevent special treatment of the `$','[',']', and `,' characters.
.TP
\fBntrans\fP [\fIinchars\fP [\fIoutchars\fP]]
Set or unset the filename character translation mechanism.  If no
arguments are specified, the filename character translation mechanism is
unset.  If arguments are specified, characters in remote filenames are
translated during
.B mput
commands and
.B put
commands issued without a specified remote target filename.  If
arguments are specified, characters in local filenames are translated
during
.B mget
commands and
.B get
commands issued without a specified local target filename.  This command
is useful when connecting to a non-UNIX remote computer with different
file naming conventions or practices.  Characters in a filename matching
a character in
.I inchars
are replaced with the corresponding character in
.IR outchars .
If the character's position in
.I inchars
is longer than the length of
.IR outchars ,
the character is deleted from the file name.
.TP
\fBopen\fP \fIhost\fP [\fIport\fP] [\fB\-forward\fP]
Establish a connection to the specified
.I host
.SM FTP
server.  An optional port number may be supplied, in which case,
.B ftp
will attempt to contact an
.SM FTP
server at that port.  If the
.B auto-authenticate
option is on (default),
.B ftp
will attempt to authenticate to the
.SM FTP
server by sending the
.SM AUTH
command, using whichever authentication types which are locally
supported.  Once an authentication type is accepted, an authentication
protocol will proceed by issuing
.SM ADAT
commands.  If the
.B auto-login
option is on (default),
.B ftp
will also attempt to automatically log the user in to the
.SM FTP
server (see below).  If the
.B \-forward
option is specified,
.B ftp
will forward a copy of the user's Kerberos tickets to the remote host.
.TP
.B passive
Toggle passive data transfer mode.  In passive mode, the client initiates
the data connection by listening on the data port.  Passive mode may
be necessary for operation from behind firewalls which do not permit
incoming connections.
.TP
.B private
Set the protection level on data transfers to ``private''.  Data
transmissions are confidentiality and integrity protected by encryption.
If no
.SM ADAT
command succeeded, then the only possible level is ``clear''.
.TP
.B prompt
Toggle interactive prompting.  Interactive prompting occurs during
multiple file transfers to allow the user to selectively retrieve or
store files.  If prompting is turned off (default is on), any
.B mget
or
.B mput
will transfer all files, and any
.B mdelete
will delete all files.
.TP
\fBprotect\fP [\fIprotection-level\fP]
Set the protection level on data transfers to
.IR protection-level .
The valid protection levels are ``clear'' for unprotected data
transmissions, ``safe'' for data transmissions integrity protected by
cryptographic checksum, and ``private'' for data transmissions
confidentiality and integrity protected by encryption.  If no
.SM ADAT
command succeeded, then the only possible level is ``clear''.  If no
level is specified, the current level is printed.  The default
protection level is ``clear''.
.TP
\fBproxy\fP \fIftp-command\fP
Execute an ftp command on a secondary control connection.  This command
allows simultaneous connection to two remote ftp servers for
transferring files between the two servers.  The first
.B proxy
command should be an
.B open  ,
to establish the secondary control connection.  Enter the command 
"proxy ?" to see other ftp commands executable on the secondary connection.
The following commands behave differently when prefaced by
.BR proxy :
.B open
will not define new macros during the auto-login process,
.B close
will not erase existing macro definitions,
.B get
and
.B mget
transfer files from the host on the primary control connection to the
host on the secondary control connection, and
.BR put ,
.BR mput ,
and
.B append
transfer files from the host on the secondary control connection to the
host on the primary control connection.  Third party file transfers
depend upon support of the ftp protocol
.SM PASV
command by the server on the secondary control connection.
.TP
\fBput\fP \fIlocal-file\fP [\fIremote-file\fP]
Store a local file on the remote machine.  If
.I remote-file
is left unspecified, the local file name is used after processing
according to any
.B ntrans
or
.B nmap
settings in naming the remote file.  File transfer uses the current
settings for
.BR type ,
.BR format ,
.BR mode ,
and
.BR structure .
.TP
.B pwd
Print the name of the current working directory on the remote machine.
.TP
.B quit
A synonym for
.BR bye .
.TP
\fBquote\fP \fIarg1\fP [\fIarg2\fP] [\fI...\fP]
The arguments specified are sent, verbatim, to the remote
.SM FTP
server.
.TP
\fBrecv\fP \fIremote-file\fP [\fIlocal-file\fP]
A synonym for get.
.TP
\fBreget\fP \fIremote-file\fP [\fIlocal-file\fP]
Reget acts like get, except that if
.I local-file
exists and is smaller than
.IR remote-file ,
.I local-file
is presumed to be a partially transferred copy of
.I remote-file
and the transfer is continued from the apparent point of failure.  This
command is useful when transferring very large files over networks that
are prone to dropping connections.
.TP
\fBremotehelp\fP [\fIcommand-name\fP]
Request help from the remote
.SM FTP
server.  If a
.I command-name
is specified it is supplied to the server as well.
.TP
\fBremotestatus\fP [\fIfile-name\fP]
With no arguments, show status of remote machine.  If
.I file-name
is specified, show status of
.I file-name
on remote machine.
.TP
\fBrename\fP [\fIfrom\fP] [\fIto\fP]
Rename the file
.I from
on the remote machine, to the file
.IR to .
.TP
.B reset
Clear reply queue.  This command re-synchronizes command/reply
sequencing with the remote ftp server.  Resynchronization may be
necessary following a violation of the ftp protocol by the remote
server.
.TP
\fBrestart\fP \fImarker\fP
Restart the immediately following
.B get
or
.B put
at the indicated
.IR marker .
On UNIX systems, marker is usually a byte offset into the file.
.TP
\fBrmdir\fP \fIdirectory-name\fP
Delete a directory on the remote machine.
.TP
.B runique
Toggle storing of files on the local system with unique filenames.  If a
file already exists with a name equal to the target local filename for a
.B get
or
.B mget
command, a ".1" is appended to the name.  If the resulting name matches
another existing file, a ".2" is appended to the original name.  If this
process continues up to ".99", an error message is printed, and the
transfer does not take place.  The generated unique filename will be
reported.  Note that
.B runique
will not affect local files generated from a shell command (see below).
The default value is off.
.TP
.B safe
Set the protection level on data transfers to ``safe''.  Data
transmissions are integrity-protected by cryptographic checksum.  If no
.SM ADAT
command succeeded, then the only possible level is ``clear''.
.TP
\fBsend\fP \fIlocal-file\fP [\fIremote-file\fP]
A synonym for put.
.TP
.B sendport
Toggle the use of
.SM PORT
commands.  By default,
.B ftp
will attempt to use a
.SM PORT
command when establishing a connection for each data transfer.  The use
of
.SM PORT
commands can prevent delays when performing multiple file transfers.  If
the
.SM PORT
command fails,
.B ftp
will use the default data port.  When the use of
.SM PORT
commands is disabled, no attempt will be made to use
.SM PORT
commands for each data transfer.  This is useful for certain
.SM FTP
implementations which do ignore
.SM PORT
commands but, incorrectly, indicate they've been accepted.
.TP
\fBsite\fP \fIarg1\fP [\fIarg2\fP] [\fI...\fP]
The arguments specified are sent, verbatim, to the remote
.SM FTP
server as a
.SM SITE
command.
.TP
\fBsize\fP \fIfile-name\fP
Return size of
.I file-name
on remote machine.
.TP
.B status
Show the current status of
.BR ftp .
.TP
\fBstruct\fP \fIstruct-name\fP
Set the file transfer
.I structure
to
.IR struct-name .
By default ``stream'' structure is used.
.TP
.B sunique
Toggle storing of files on remote machine under unique file names.
Remote ftp server must support ftp protocol
.SM STOU
command for successful completion.  The remote server will report unique
name.  Default value is off.
.TP
.B system
Show the type of operating system running on the remote machine.
.TP
.B tenex
Set the file transfer type to that needed to talk to
.SM TENEX
machines.
.TP
.B trace
Toggle packet tracing.
.TP
\fBtype\fP [\fItype-name\fP]
Set the file transfer
.B type
to
.IR type-name .
If no type is specified, the current type is printed.  The default type
is network
.SM ASCII.
.TP
\fBumask\fP [\fInewmask\fP]
Set the default umask on the remote server to
.IR newmask .
If
.I newmask
is omitted, the current umask is printed.
.TP
\fBuser\fP \fIuser-name\fP [\fIpassword\fP] [\fIaccount\fP]
Identify yourself to the remote
.SM FTP
server.  If the
.I password
is not specified and the server requires it,
.B ftp
will prompt the user for it (after disabling local echo).  If an
.I account
field is not specified, and the
.SM FTP
server requires it, the user will be prompted for it.  If an
.I account
field is specified, an account command will be relayed to the remote
server after the login sequence is completed if the remote server did
not require it for logging in.  Unless
.B ftp
is invoked with ``auto-login'' disabled, this process is done
automatically on initial connection to the
.SM FTP
server.
.TP
.B verbose
Toggle verbose mode.  In verbose mode, all responses from the
.SM FTP
server are displayed to the user.  In addition, if verbose is on, when a
file transfer completes, statistics regarding the efficiency of the
transfer are reported.  By default, verbose is on.
.TP
\fB \&? [\fIcommand\fP]
A synonym for help.
.PP
Command arguments which have embedded spaces may be quoted with quote
`"' marks.
.SH ABORTING A FILE TRANSFER
To abort a file transfer, use the terminal interrupt key (usually
Ctrl-C).  Sending transfers will be immediately halted.  Receiving
transfers will be halted by sending a 
.SM FTP
protocol
.SM ABOR
command to the remote server, and discarding any further data received.
The speed at which this is accomplished depends upon the remote server's
support for
.SM ABOR
processing.  If the remote server does not support the
.SM ABOR
command, an `ftp>' prompt will not appear until the remote server has
completed sending the requested file.
.PP
The terminal interrupt key sequence will be ignored when
.B ftp
has completed any local processing and is awaiting a reply from the
remote server.  A long delay in this mode may result from the
.SM ABOR
processing described above, or from unexpected behavior by the remote
server, including violations of the ftp protocol.  If the delay results
from unexpected remote server behavior, the local
.B ftp
program must be killed by hand.
.SH FILE NAMING CONVENTIONS
Files specified as arguments to
.B ftp
commands are processed according to the following rules.
.TP
1.
If the file name `\fB-\fP' is specified,
.I stdin
(for reading) or
.I stdout
(for writing) is used.
.TP
2.
If the first character of the file name is `\&|', the remainder of the
argument is interpreted as a shell command.
.B Ftp
then forks a shell, using
.IR popen (3)
with the argument supplied, and reads from (writes to) stdout (stdin).
If the shell command includes spaces, the argument must be quoted; e.g.
``" ls -lt"''.  A particularly useful example of this mechanism is:
``dir more''.
.TP
3.
Failing the above checks, if ``globbing'' is enabled, local file names
are expanded according to the rules used in
.IR csh (1);
c.f. the
.B glob
command.  If the
.B ftp
command expects a single local file (.e.g.
.BR put ),
only the first filename generated by the ``globbing'' operation is used.
.TP
4.
For
.B mget
commands and
.B get
commands with unspecified local file names, the local filename is the
remote filename, which may be altered by a
.BR case ,
.BR ntrans ,
or
.B nmap
setting.  The resulting filename may then be altered if
.B runique
is on.
.TP
5.
For
.B mput
commands and
.B put
commands with unspecified remote file names, the remote filename is the
local filename, which may be altered by a
.B ntrans
or
.B nmap
setting.  The resulting filename may then be altered by the remote
server if
.B sunique
is on.
.SH FILE TRANSFER PARAMETERS
The FTP specification specifies many parameters which may affect a file
transfer.  The
.B type
may be one of ``ascii'', ``image'' (binary), ``ebcdic'', and ``local
byte size'' (mostly for PDP-10's and PDP-20's).
.B Ftp
supports the ascii and image types of file transfer, plus local byte
size 8 for
.B tenex
mode transfers.
.PP
.B Ftp
supports only the default values for the remaining file transfer
parameters:
.BR mode ,
.BR form ,
and
.BR struct .
.SH THE .netrc FILE
The
.I .netrc
file contains login and initialization information used by the
auto-login process.  It resides in the user's home directory.  The
following tokens are recognized; they may be separated by spaces, tabs,
or new-lines:
.TP
\fBmachine\fP \fIname\fP
Identify a remote machine
.IR name .
The auto-login process searches the
.I .netrc
file for a
.B machine
token that matches the remote machine specified on the
.B ftp
command line or as an
.B open
command argument.  Once a match is made, the subsequent
.I .netrc
tokens are processed, stopping when the end of file is reached or
another
.B machine
or a
.B default
token is encountered.
.TP
.B default
This is the same as
.B machine
.I name
except that
.B default
matches any name.  There can be only one
.B default
token, and it must be after all
.B machine
tokens.  This is normally used as:
.sp
     default login anonymous password user@site
.sp
thereby giving the user
.I automatic
anonymous ftp login to machines not specified in
.IR .netrc .
This can be overridden by using the
.B \-n
flag to disable auto-login.
.TP
\fBlogin\fP \fIname\fP
Identify a user on the remote machine.  If this token is present, the
auto-login process will initiate a login using the specified
.IR name .
.TP
\fBpassword\fP \fIstring\fP
Supply a password.  If this token is present, the auto-login process
will supply the specified string if the remote server requires a
password as part of the login process.  Note that if this token is
present in the
.I .netrc
file for any user other than
.IR anonymous ,
.B ftp
will abort the auto-login process if the
.I .netrc
is readable by anyone besides the user.
.TP
\fBaccount\fP \fIstring\fP
Supply an additional account password.  If this token is present, the
auto-login process will supply the specified string if the remote server
requires an additional account password, or the auto-login process will
initiate an
.SM ACCT
command if it does not.
.TP
\fBmacdef\fP \fIname\fP
Define a macro.  This token functions like the
.B ftp
.B macdef
command functions.  A macro is defined with the specified name; its
contents begin with the next
.I .netrc
line and continue until a null line (consecutive new-line characters) is
encountered.  If a macro named
.B init
is defined, it is automatically executed as the last step in the
auto-login process.
.SH ENVIRONMENT
.B Ftp
utilizes the following environment variables.
.TP
.SM HOME
For default location of a
.I .netrc
file, if one exists.
.TP
.SM SHELL
For default shell.
.SH SEE ALSO
.IR ftpd (8)
.PP
Lunt, S. J., FTP Security Extensions, Internet Draft, November 1993.
.SH HISTORY
The
.B ftp
command appeared in 4.2BSD.
.SH BUGS
Correct execution of many commands depends upon proper behavior by the
remote server.
.PP
An error in the treatment of carriage returns in the 4.2BSD ascii-mode
transfer code has been corrected.  This correction may result in
incorrect transfers of binary files to and from 4.2BSD servers using the
ascii type.  Avoid this problem by using the binary image type.
