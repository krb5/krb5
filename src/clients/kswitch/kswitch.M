.\" clients/kswitch/kswitch.M
.\"
.\" Copyright 2011 by the Massachusetts Institute of Technology.
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
.TH KSWITCH 1
.SH NAME
kswitch \- switch primary credential cache
.SH SYNOPSIS
\fBkswitch\fP {\fB\-c\fP \fIcachename\fP | \fB\-p\fP \fIprincipal\fP}
.SH DESCRIPTION
.I kswitch
makes the specified credential cache the primary cache for the
collection, if a cache collection is available.
.SH OPTIONS
.TP
.B \-c
.I cachename
directly specifies the credential cache to be made primary.
.TP
.B \-p
.I principal
causes the cache collection to be searched for a cache containing
credentials for \fIprincipal\fP.  If one is found, that collection is
made primary.
.SH ENVIRONMENT
.B kswitch
uses the following environment variables:
.TP "\w'.SM KRB5CCNAME\ \ 'u"
.SM KRB5CCNAME
Location of the default Kerberos 5 credentials (ticket) cache, in the
form \fItype\fP:\fIresidual\fP.  If no type prefix is present, the
\fBFILE\fP type is assumed.  The type of the default cache may
determine the availability of a cache collection; for instance, a
default cache of type \fBDIR\fP causes caches within the directory to
be present in the collection.
.SH FILES
.TP "\w'/tmp/krb5cc_[uid]\ \ 'u"
/tmp/krb5cc_[uid]
default location of Kerberos 5 credentials cache 
([uid] is the decimal UID of the user).
.SH SEE ALSO
kinit(1), kdestroy(1), klist(1), kerberos(1)
