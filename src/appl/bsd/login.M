.\"	login.1
.\"
.TH LOGIN 8C "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
login \- kerberos enhanced login program
.SH SYNOPSIS
.B /sbin/login.krb5
[
.B \-fF [username]
]
.SH DESCRIPTION
.I login
is a modification of the BSD login program which is used for two functions.
It is the sub-process used by krlogind and telnetd to initiate a user session
and it is a replacement for the command-line login program which, when 
invoked with a password, acquires Kerberos tickets for the user.
.PP
.I login 
will prompt for a username, or take one on the command line, as
.I login username
and will then prompt for a password. This password will be used to acquire
Kerberos Version 5 tickets and Kerberos Version 4 tickets (if
possible.) It will also attempt to run 
.I aklog
to get \fIAFS\fP tokens for the user. The version 5 tickets will be
tested against a local 
.I v5srvtab
if it is available, in order to verify the tickets, before letting the
user in. However, if the password matches the entry in
\fI/etc/passwd\fP the user will be unconditionally allowed (permitting
use of the machine in case of network failure.)
.PP
.I login
is also configured via 
.I krb5.conf
using the
.I \[login\]
stanza. A collection of options dealing with initial authentication are
provided:
.IP krb5_get_tickets
Use password to get V5 tickets. Default value true.
.IP krb4_get_tickets
Use password to get V4 tickets. Default value true.
.IP krb4_convert
Use Kerberos conversion daemon to get V4 tickets. Default value
true. If false, gets initial ticket directly, which does not currently
work with non MIT-V4 salt types (such as the AFS3 salt type.)
.IP krb_run_aklog
Attempt to run aklog. Default value true.
.IP aklog_path
Where to find it [not yet implemented.] Default value 
.I $(prefix)/bin/aklog.
.IP accept_passwd = 0
Don't accept plaintext passwords [not yet implemented]. Default value false.

.SH DIAGNOSTICS
All diagnostic messages are returned on the connection or tty
associated with
.BR stderr.
.PP
.SH SEE ALSO
rlogind(8C), rlogin(1C), telnetd(8c)
.SH BUGS
Should use a config file to select use of V5, V4, and AFS, as well as
policy for startup.
