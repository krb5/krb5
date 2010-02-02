.\" clients/klist/klist.M
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
.TH KLIST 1
.SH NAME
klist \- list cached Kerberos tickets
.SH SYNOPSIS
\fBklist\fP [\fB\-e\fP] [[\fB\-c\fP] [\fB\-f\fP] 
[\fB\-s\fP] [\fB\-a\fP  [\fB\-n\fP]]]
[\fB\-k\fP [\fB\-t\fP] [\fB\-K\fP]]
[\fIcache_name\fP | \fIkeytab_name\fP]
.br
.SH DESCRIPTION
.I Klist
lists the Kerberos principal and Kerberos tickets held in a credentials
cache, or the keys held in a
.B keytab
file.
.SH OPTIONS
.TP
.B \-e
displays the encryption types of the session key and the ticket for each
credential in the credential cache, or each key in the keytab file.
.TP
.B \-c
List tickets held in a credentials cache.  This is the default if
neither
.B \-c
nor
.B \-k
is specified.
.TP
.B \-f
shows the flags present in the credentials, using the following
abbreviations:
.sp
.nf
.in +.5i
F	\fBF\fPorwardable
f	\fBf\fPorwarded
P	\fBP\fProxiable
p	\fBp\fProxy
D	post\fBD\fPateable
d	post\fBd\fPated
R	\fBR\fPenewable
I	\fBI\fPnitial
i	\fBi\fPnvalid
H	\fBH\fPardware authenticated
A	pre\fBA\fPuthenticated
T	\fBT\fPransit policy checked
O	\fBO\fPkay as delegate
a	\fBa\fPnonymous
.in -.5i
.fi
.TP
.B \-s
causes
.B klist
to run silently (produce no output), but to still set the exit status
according to whether it finds the credentials cache.  The exit status is
`0' if
.B klist
finds a credentials cache, and `1' if it does not or if the tickets are
 expired.
.TP
.B \-a
display list of addresses in credentials.
.TP
.B \-n
show numeric addresses instead of reverse-resolving addresses.
.TP
\fB\-k\fP
List keys held in a
.B keytab
file.  
.TP
.B \-t
display the time entry timestamps for each keytab entry in the keytab
file.
.TP
.B \-K
display the value of the encryption key in each keytab entry in the
keytab file.
.PP
If
.I cache_name
or
.I keytab_name
is not specified, klist will display the credentials in the default
credentials cache or keytab file as appropriate.  If the
.B KRB5CCNAME
environment variable is set, its value is used to name the default
ticket cache.
.SH ENVIRONMENT
.B Klist
uses the following environment variables:
.TP "\w'.SM KRB5CCNAME\ \ 'u"
.SM KRB5CCNAME
Location of the Kerberos 5 credentials (ticket) cache.
.SH FILES
.TP "\w'/tmp/krb5cc_[uid]\ \ 'u"
/tmp/krb5cc_[uid]
default location of Kerberos 5 credentials cache 
([uid] is the decimal UID of the user).
.TP
/etc/krb5.keytab
default location for the local host's
.B keytab
file.
.SH SEE ALSO
kinit(1), kdestroy(1), krb5(3)
