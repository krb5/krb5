.\" clients/kdestroy/kdestroy.M
.\"
.\" Copyright 1992 by the Massachusetts Institute of Technology.
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
.TH KDESTROY 1
.SH NAME
kdestroy \- destroy Kerberos tickets
.SH SYNOPSIS
.B kdestroy
[\fB\-5\fP] [\fB\-4\fP] [\fB\-q\fP] [\fB\-c\fP \fIcache_name]
.br
.SH DESCRIPTION
The
.I kdestroy
utility destroys the user's active Kerberos authorization tickets by
writing zeros to the specified credentials cache that contains them.  If
the credentials cache is not specified, the default credentials cache is
destroyed.
If kdestroy was built with Kerberos 4 support, the default behavior is to
destroy both Kerberos 5 and Kerberos 4 credentials.  Otherwise, kdestroy 
will default to destroying only Kerberos 5 credentials.
.SH OPTIONS
.TP
.B \-5
destroy Kerberos 5 credentials.  This overrides whatever the default built-in
behavior may be.  This option may be used with
.B \-4
.
.TP
.B \-4
destroy Kerberos 4 credentials.  This overrides whatever the default built-in
behavior may be.  This option is only available if kinit was built
with Kerberos 4 compatibility.  This option may be used with 
.B \-5
.
.TP
.B \-q
Run quietly.  Normally
.B kdestroy
beeps if it fails to destroy the user's tickets.  The
.B \-q
flag suppresses this behavior.
.TP
\fB\-c\fP \fIcache_name\fP
use
.I cache_name
as the credentials (ticket) cache name and location; if this option is
not used, the default cache name and location are used.
.sp
The default credentials cache may vary between systems.  If the
.SM KRB5CCNAME
environment variable is set, its value is used to name the default
ticket cache.
.PP
Most installations recommend that you place the
.I kdestroy
command in your
.I .logout
file, so that your tickets are destroyed automatically when you log out.
.SH ENVIRONMENT
.B Kdestroy
uses the following environment variables:
.TP "\w'.SM KRB5CCNAME\ \ 'u"
.SM KRB5CCNAME
Location of the Kerberos 5 credentials (ticket) cache.
.TP "\w'.SM KRBTKFILE\ \ 'u"
.SM KRBTKFILE
Filename of the Kerberos 4 credentials (ticket) cache.
.SH FILES
.TP "\w'/tmp/krb5cc_[uid]\ \ 'u"
/tmp/krb5cc_[uid]
default location of Kerberos 5 credentials cache 
([uid] is the decimal UID of the user).
.TP "\w'/tmp/tkt[uid]\ \ 'u"
/tmp/tkt[uid]
default location of Kerberos 4 credentials cache 
([uid] is the decimal UID of the user).
.SH SEE ALSO
kinit(1), klist(1), krb5(3)
.SH BUGS
.PP
Only the tickets in the specified credentials cache are destroyed.
Separate ticket caches are used to hold root instance and password
changing tickets.  These should probably be destroyed too, or all of a
user's tickets kept in a single credentials cache.
