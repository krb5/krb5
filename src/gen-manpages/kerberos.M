.\" Copyright 1989 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information,
.\" please see the file <mit-copyright.h>.
.\" "
.TH KERBEROS 1
.SH NAME
kerberos \- introduction to the Kerberos system
.SH DESCRIPTION
The Kerberos system authenticates individual users in a network
environment.  After authenticating yourself to Kerberos, you can use
network utilities such as
.IR rlogin ,
.IR rcp ,
and
.IR rsh
without having to present passwords to remote hosts and without having
to bother with
.I \.rhosts
files.  Note that these utilities will work without passwords only if
the remote machines you deal with support the Kerberos system.
.PP
If you enter your username and
.I kinit
responds with this message:
.PP
kinit(v5): Client not found in Kerberos database while getting initial
credentials
.PP
you haven't been registered as a Kerberos user.  See your system
administrator.
.PP
A Kerberos name usually contains three parts.  The first is the
.IR primary ,
which is usually a user's or service's name.  The second is the
.IR instance ,
which in the case of a user is usually null.  Some users may have
privileged instances, however, such as ``root'' or ``admin''.  In the
case of a service, the instance is the fully qualified name of the
machine on which it runs; i.e. there can be an
.I rlogin
service running on the machine ABC, which is different from the rlogin
service running on the machine XYZ.  The third part of a Kerberos name
is the
.IR realm .
The realm corresponds to the Kerberos service providing authentication
for the principal.
.PP
When writing a Kerberos name, the principal name is separated from the
instance (if not null) by a slash, and the realm (if not the local
realm) follows, preceded by an ``@'' sign.  The following are examples
of valid Kerberos names:
.sp
.nf
.in +8
david
jennifer/admin
joeuser@BLEEP.COM
cbrown/root@FUBAR.ORG
.in -8
.fi
.PP
When you authenticate yourself with Kerberos you get an initial Kerberos
.IR ticket .
(A Kerberos ticket is an encrypted protocol message that provides
authentication.)  Kerberos uses this ticket for network utilities such
as
.I rlogin
and
.IR rcp .
The ticket transactions are done transparently, so you don't have to
worry about their management.
.PP
Note, however, that tickets expire.  Privileged tickets, such as those
with the instance ``root'', expire in a few minutes, while tickets that
carry more ordinary privileges may be good for several hours or a day,
depending on the installation's policy.  If your login session extends
beyond the time limit, you will have to re-authenticate yourself to
Kerberos to get new tickets.  Use the
.IR kinit
command to re-authenticate yourself.
.PP
If you use the
.I kinit
command to get your tickets, make sure you use the
.I kdestroy
command to destroy your tickets before you end your login session.  You
should put the
.I kdestroy
command in your
.I \.logout
file so that your tickets will be destroyed automatically when you
logout.  For more information about the
.I kinit
and
.I kdestroy
commands, see the
.IR kinit (1)
and
.IR kdestroy (1)
manual pages.
.PP
Kerberos tickets can be forwarded.  In order to forward tickets, you
must request
.I forwardable
tickets when you
.IR kinit .
Once you have forwardable tickets, most Kerberos programs have a command
line option to forward them to the remote host.
.PP
Currently, Kerberos support is available for the following network
services:
.IR rlogin ,
.IR rsh ,
.IR rcp ,
.IR telnet ,
.IR ftp ,
.I krdist
(a Kerberized version of
.IR rdist ),
.I ksu
(a Kerberized version of
.IR su ),
.IR login ,
and
.IR Xdm .
.SH "SEE ALSO"
kdestroy(1), kinit(1), klist(1), kpasswd(1), rsh (1), rcp(1), rlogin(1),
telnet(1), ftp(1), krdist(1), ksu(1), sclient(1), xdm(1), des_crypt(3),
hash(3), krb5strings(3), krb5.conf(5), kdc.conf(5), kadmin(8),
kadmind(8), kdb5_util(8), telnetd(8), ftpd(8), rdistd(8), sserver(8),
klogind(8c), kshd(8c), login(8c)
.SH BUGS
.SH AUTHORS
Steve Miller, MIT Project Athena/Digital Equipment Corporation
.br
Clifford Neuman, MIT Project Athena
.SH HISTORY
Kerberos was developed at MIT.  OpenVision rewrote and donated the
administration server, which is used in the current version of Kerberos
5.
.SH RESTRICTIONS
Copyright 1985,1986,1989-1996,2002 Massachusetts Institute of Technology
