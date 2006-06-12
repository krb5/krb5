.\" krb524/k524init.M
.\"
.\" Copyright 2005 by the Massachusetts Institute of Technology.
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
.TH KRB524INIT 1
.SH NAME
krb524init \- Obtain Kerberos V4 tickets from Kerberos V5 tickets
.SH SYNOPSIS
\fBkrb524init\fP [\fB\-n\fP] [\fB\-p\fP \fIprincipal\fP]
.SH DESCRIPTION
.I krb524init
converts a V5 credential to a V4 credential by querying a remote krb524d
server and stores it in a V4 ticket cache.  The credential is
.I principal
or "krbtgt" at the V5 ticket cache's default principal's realm if not
specified.
.SH OPTIONS
.TP
.B \-n
By default, the V4 ticket cache is initialized.  If this option is given,
the converted credential is instead added to the existing ticket cache.
.TP
\fB\-p\fP \fIprincipal\fP
Convert
.I principal
rather than krbtgt.
.SH SEE ALSO
kinit(1), krb524d(8)
