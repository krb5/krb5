.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1989,1991 by the Massachusetts Institute of Technology.
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
.\" permission.  M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
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
.br
.SH FILES
.IP KRB5ROOT/krb.conf 23
The location of krb.conf is defined at compile time by KRB5ROOT, this
is /krb5 by default.
.br
.SH SEE ALSO
krb.realms(5)
