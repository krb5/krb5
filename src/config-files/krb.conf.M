.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1989,1991 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information,
.\" please see the file <krb5/copyright.h>.
.\"
.TH KRB.CONF 5 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
krb.conf \- Kerberos configuration file
.SH DESCRIPTION
.I krb.conf
contains configuration information describing the Kerberos realm and the
Kerberos key distribution center (KDC) servers for known realms.
.PP
.I krb.conf
contains two sections.  The first section consists of only the first
line in the file.  This line identifies the default realm to be used in
a client host's Kerberos activity.
.PP
The second section consists of the remainder of the file.  Each
subsequent line maps a realm name to a host running a KDC for that
realm.  The first token on the line is the realm name, and the second is
the hostname of a host running a KDC for that realm.  The words "admin
server" following the hostname indicate that the host also provides an
administrative database server.  For example, this file:
.sp
.nf
.in +1i
FOO.MIT.EDU
ATHENA.MIT.EDU kerberos-1.mit.edu admin server
ATHENA.MIT.EDU kerberos-2.mit.edu
FOO.MIT.EDU bar-kerberos.mit.edu
LCS.MIT.EDU kerberos.lcs.mit.edu admin server
.in -1i
.fi
.sp
configures the local host to run in the FOO.MIT.EDU realm by default,
identifies kerberos-1.mit.edu and kerberos-2.mit.edu as KDC's for the
ATHENA.MIT.EDU realm, bar-kerberos.mit.edu as a KDC for the FOO.MIT.EDU
realm, and kerberos.lcs.mit.edu as a KDC for the LCS.MIT.EDU.
In addition, kerberos.lcs.mit.edu provides an administrative server for
the LCS realm, and kerberos-1.mit.edu provides such a server for the
Athena realm.
.SH SEE ALSO
krb.realms(5)
