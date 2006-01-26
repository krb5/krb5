.\" appl/bsd/v4rcp.M
.TH RCP 1 \*h
.SH NAME
v4rcp \- back end for Kerberos V4 rcp
.SH SYNOPSIS
.B v4rcp
.I not invoked by users
.SH DESCRIPTION
This program is
.B not
for user execution. The usage message indicates this. 
.PP
Kerberos Version 4 
.I rsh
did not support encryption. In order to perform
encrypted file transfer, the version 4
.I rcp
program did a second authentication, directly to the 
.I rcp
process at the other end. This meant that
.I rcp
needed to be
.IR setuid
to root in order to read the
.IR krb-srvtab
file on the remote end.
.PP
Rather than add this complexity into the main Kerberos 5 
.I rcp
the Kerberos 5 
.I kshd
instead detects the use of Kerberos 4 authentication, and checks the
command for the program name
.I rcp
and then substitutes the full pathname of
.I v4rcp
instead.  Since
.I v4rcp
is installed
.IR setuid
to root, it can perform the the authentication and get the session key
needed to encrypt the file transfer.
.PP
Kerberos 5 
.I rcp 
instead uses the encryption support built in to Kerberos 5
.I rsh
and
.I kshd
directly.
.SH SEE ALSO
rsh(1), rcp(1), kshd(8)
