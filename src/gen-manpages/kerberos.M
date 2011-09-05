.\" Copyright 1989, 2011 by the Massachusetts Institute of Technology.
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
Kerberos-enabled programs without having to present passwords.
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
.SH "ENVIRONMENT VARIABLES"
Several environment variables affect the operation of Kerberos-enabled
programs.  These include:
.TP
.B KRB5CCNAME
Specifies the location of the credential cache, in the form
\fITYPE\fP:\fIresidual\fP.  If no type prefix is present, the
\fBFILE\fP type is assumed and \fIresidual\fP is the pathname of the
cache file.  A collection of multiple caches may be used by specifying
the \fBDIR\fP type and the pathname of a private directory (which must
already exist).  The default cache file is /tmp/krb5cc_\fIuid\fP where
\fIuid\fP is the decimal user ID of the user.
.TP
.B KRB5_KTNAME
Specifies the location of the keytab file, in the form
\fITYPE\fP:\fIresidual\fP.  If no type is present, the \fBFILE\fP type
is assumed and \fIresidual\fP is the pathname of the keytab file.  The
default keytab file is /etc/krb5.keytab.
.TP
.B KRB5_CONFIG
Specifies the location of the Kerberos configuration file.  The
default is /etc/krb5.conf.
.TP
.B KRB5_KDC_PROFILE
Specifies the location of the KDC configuration file, which contains
additional configuration directives for the Key Distribution Center
daemon and associated programs.  The default is
/usr/local/var/krb5kdc/kdc.conf.
.TP
.B KRB5RCACHETYPE
Specifies the default type of replay cache to use for servers.  Valid
types include "dfl" for the normal file type and "none" for no replay
cache.
.B KRB5RCACHEDIR
Specifies the default directory for replay caches used by servers.
The default is the value of the \fBTMPDIR\fP environment variable, or
/var/tmp if \fBTMPDIR\fP is not set.
.TP
.B KRB5_TRACE
Specifies a filename to write trace log output to.  Trace logs can
help illuminate decisions made internally by the Kerberos libraries.
The default is not to write trace log output anywhere.
.PP
Most environment variables are disabled for certain programs, such as
login system programs and setuid programs, which are designed to be
secure when run within an untrusted process environment.
.SH "SEE ALSO"
kdestroy(1), kinit(1), klist(1), kswitch(1), kpasswd(1), ksu(1),
krb5.conf(5), kdc.conf(5), kadmin(1), kadmind(8), kdb5_util(8),
krb5kdc(8)
.SH BUGS
.SH AUTHORS
Steve Miller, MIT Project Athena/Digital Equipment Corporation
.br
Clifford Neuman, MIT Project Athena
.br
Greg Hudson, MIT Kerberos Consortium
.SH HISTORY
The MIT Kerberos 5 implementation was developed at MIT, with
contributions from many outside parties.  It is currently maintained
by the MIT Kerberos Consortium.
.SH RESTRICTIONS
Copyright 1985,1986,1989-1996,2002,2011 Massachusetts Institute of Technology
