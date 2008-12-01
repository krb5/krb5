.\" appl/sample/sserver/sserver.M
.\"
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" Export of this software from the United States of America may
.\"   require a specific license from the United States Government.
.\"   It is the responsibility of any person or organization contemplating
.\"   export to obtain such a license before exporting.
.\" 
.\" WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
.\" distribute this software and its documentation for any purpose and
.\" without fee is hereby granted, provided that the above copyright
.\" notice appear in all copies and that both that copyright notice and
.\" this permission notice appear in supporting documentation, and that
.\" the name of M.I.T. not be used in advertising or publicity pertaining
.\" to distribution of the software without specific, written prior
.\" permission.  Furthermore if you modify this software you must label
.\" your software as modified software and not distribute it in such a
.\" fashion that it might be confused with the original M.I.T. software.
.\" M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" "
.TH SSERVER 8
.SH NAME
sserver \- sample Kerberos version 5 server
.SH SYNOPSIS
.B sserver
[
.I \-p
port ] [
.I \-S
keytab ] [
.I server_port
]
.br
.SH DESCRIPTION

\fIsserver\fP and \fIsclient\fP are a simple demonstration
client/server application.  When \fIsclient\fP connects to
\fIsserver\fP, it performs a Kerberos authentication, and then
\fIsserver\fP returns to \fIsclient\fP the Kerberos
principal which was used for the Kerberos authentication.  It makes a
good test that Kerberos has been successfully installed on a machine.
.PP
The service name used by \fIsserver\fP and \fIsclient\fP is
\fBsample\fP.  Hence, \fIsserver\fP will require that there be a keytab
entry for the service "sample/hostname.domain.name@REALM.NAME".  This
keytab is generated using the
.IR kadmin(8)
program.  The keytab file is usually installed as "/etc/krb5.keytab".
.PP
The 
.B \-S
option allows for a different keytab than the default.
.PP
\fIsserver\fP is normally invoked out of 
.IR inetd(8), 
using a line in
/etc/inetd.conf that looks like this:
.PP
sample  stream  tcp     nowait  root /usr/local/sbin/sserver	sserver
.PP
Since \fBsample\fP is normally not a port defined in /etc/services, you will
usually have to add a line to /etc/services which looks like this:
.PP
sample          13135/tcp
.PP
When using \fIsclient,\fP you will first have to have an entry in the Kerberos
database, by using 
.IR kadmin(8),
and then you have to get Kerberos
tickets, by using 
.IR kinit(8).  
Also, if you are running the \fIsclient\fP
program on a different host than the \fIsserver\fP it will be
connecting to, be
sure that both hosts have an entry in /etc/services for the \fBsample\fP tcp
port, and that the same port number is in both files.
.PP
When you run sclient you should see something like this:
.PP
sendauth succeeded, reply is:
.br
reply len 32, contents:
.br
You are nlgilman@JIMI.MIT.EDU
.br
.SH COMMON ERROR MESSAGES

1)  \fIkinit\fP returns the error:
.PP
kinit: Client not found in Kerberos database while getting initial credentials
.PP
This means that you didn't create an entry for your username in the
Kerberos database.
.PP
2)  \fIsclient\fP returns the error:
.PP
unknown service sample/tcp; check /etc/services
.PP
This means that you don't have an entry in /etc/services for the
\fBsample\fP tcp port.
.PP
3)  \fIsclient\fP returns the error:
.PP
connect: Connection refused
.PP
This probably means you didn't edit /etc/inetd.conf correctly, or you
didn't restart \fIinetd\fP after editing inetd.conf.
.PP
4)  \fIsclient\fP returns the error:
.PP
sclient: Server not found in Kerberos database while using sendauth
.PP
This means that the "sample/hostname@LOCAL.REALM" service was not
defined in the Kerberos database; it should be created using \fIkadmin,\fP
and a keytab file needs to be generated to make the key for that service
principal available for \fIssclient\fP.
.PP
5)  \fIsclient\fP returns the error:
.PP
sendauth rejected, error reply is:
        " No such file or directory"
.PP
This probably means \fIsserver\fP couldn't find the keytab file.  It was
probably not installed in the proper directory.
.br
.SH SEE ALSO
sclient(1), services(5), inetd(8)
