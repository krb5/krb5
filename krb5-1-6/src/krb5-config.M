.\" krb5-config.M
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
.TH KRB5-CONFIG 1
.SH NAME
krb5-config \- tool for linking against MIT Kerberos libraries
.SH SYNOPSIS
.B krb5-config
[ \fB--help\fP | \fB--all\fP | \fB--version\fP | \fB--vendor\fP | \fB--prefix\fP | 
\fB--exec-prefix\fP | \fB--cflags\fP | \fB--libs\fP libraries ]
.br
.SH DESCRIPTION
.I krb5-config
tells the application programmer what special flags to use to compile
and link programs against the installed Kerberos libraries.
.SH OPTIONS
.TP
\fB\--help\fP
print usage message.  This is the default.
.TP
\fB\--all\fP
prints version, vendor, prefix and exec-prefix.
.TP
\fB\--version\fP
prints the version of the installed Kerberos implementation.
.TP
\fB\--vendor\fP
prints the vendor of the installed Kerberos implementation.
.TP
\fB\--prefix\fP 
prints the prefix with which Kerberos was built.
.TP
\fB\--exec-prefix\fP 
prints the exec-prefix with which Kerberos was built.
.TP
\fB\--cflags\fP 
prints the compiler flags with which Kerberos was built.
.TP
\fB\--libs\fP \fIlibraries\fP 
list compiler options required to link with \fIlibraries\fP.  Possible 
values for \fIlibraries\fP are:
.sp
.nf
.in +.5i
krb5         Kerberos 5 application
gssapi       GSSAPI application with Kerberos 5 bindings
krb4         Kerberos 4 application
kadm-client  Kadmin client
kadm-server  Kadmin server
kdb          Application that accesses the kerberos database
.in -.5i
.fi
.SH SEE ALSO
kerberos(1), cc(1)
