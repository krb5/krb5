.\"	login.1
.\"
.TH LOGIN 8
.SH NAME
login.krb5 \- kerberos enhanced login program
.SH SYNOPSIS
.B login.krb5
[\fB\-p\fP] [\fB\-fFe\fP \fIusername\fP] 
[\fB\-r | \-k | \-K | \-h \fP\fIhostname\fP]
.SH DESCRIPTION
.I login.krb5
is a modification of the BSD login program which is used for two
functions.  It is the sub-process used by krlogind and telnetd to
initiate a user session and it is a replacement for the command-line
login program which, when invoked with a password, acquires Kerberos
tickets for the user.
.PP
.I login.krb5 
will prompt for a username, or take one on the command line, as
.I login.krb5 username
and will then prompt for a password. This password will be used to
acquire Kerberos Version 5 tickets and Kerberos Version 4 tickets (if
possible.) It will also attempt to run
.I aklog
to get \fIAFS\fP tokens for the user. The version 5 tickets will be
tested against a local 
.I krb5.keytab
if it is available, in order to verify the tickets, before letting the
user in. However, if the password matches the entry in
\fI/etc/passwd\fP the user will be unconditionally allowed (permitting
use of the machine in case of network failure.)
.SH OPTIONS
.TP
\fB\-p\fP
preserve the current environment
.TP
\fB\-r\fP \fIhostname\fP
pass hostname to rlogind.  Must be the last argument.
.TP
\fB\-h\fP \fIhostname\fP
pass hostname to telnetd, etc.  Must be the last argument.
.TP
\fB\-k\fP \fIhostname\fP
Use Kerberos V4 to login.  Must be the last argument.
.TP
\fB\-K\fP \fIhostname\fP
Use Kerberos V4 to login.  Must be the last argument.
.TP
\fB\-f\fP \fIname\fP
Perform pre-authenticated login, e.g., datakit, xterm, etc.; 
allows preauthenticated login as root.
.TP
\fB\-F\fP \fIname\fP
Perform pre-authenticated login, e.g., datakit, xterm, etc.; allows
preauthenticated login as root.
.TP
\fB\-e\fP \fIname\fP
Perform pre-authenticated, encrypted login.  Must do term negotiation.
.SH CONFIGURATION
.I login.krb5
is also configured via 
.I krb5.conf
using the
.I login
stanza. A collection of options dealing with initial authentication are
provided:
.IP krb5_get_tickets
Use password to get V5 tickets. Default value true.
.IP krb4_get_tickets
Use password to get V4 tickets. Default value false.
.IP krb4_convert
Use Kerberos conversion daemon to get V4 tickets. Default value
false. If false, and krb4_get_tickets is true, then login will get
the V5 tickets directly using the Kerberos V4 protocol directly.  
This does not currently work with non MIT-V4 salt types
(such as the AFS3 salt type.)  Note that if configuration parameter 
is true, and the krb524d is not running, login will hang for 
approximately a minute  under Solaris, 
due to a Solaris socket emulation bug.
.IP krb_run_aklog
Attempt to run aklog. Default value false.
.IP aklog_path
Where to find it [not yet implemented.] Default value 
.I $(prefix)/bin/aklog.
.IP accept_passwd
Don't accept plaintext passwords [not yet implemented]. Default value false.

.SH DIAGNOSTICS
All diagnostic messages are returned on the connection or tty
associated with
.BR stderr.
.PP
.SH SEE ALSO
rlogind(8), rlogin(1), telnetd(8)
.SH BUGS
Should use a config file to select use of V5, V4, and AFS, as well as
policy for startup.
