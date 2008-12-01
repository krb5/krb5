.\" clients/kinit/kinit.M
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
.TH KINIT 1
.SH NAME
kinit \- obtain and cache Kerberos ticket-granting ticket
.SH SYNOPSIS
.TP
.B kinit
.ad l
[\fB\-5\fP]
[\fB\-4\fP]
[\fB\-V\fP]
[\fB\-l\fP \fIlifetime\fP] [\fB\-s\fP \fIstart_time\fP]
[\fB\-r\fP \fIrenewable_life\fP]
[\fB\-p\fP | \fB\-P\fP]
[\fB\-f\fP | \fB\-F\fP]
[\fB\-a\fP]
[\fB\-A\fP]
[\fB\-v\fP] [\fB\-R\fP]
[\fB\-k\fP [\fB\-t\fP \fIkeytab_file\fP]] [\fB\-c\fP \fIcache_name\fP]
[\fB\-S\fP \fIservice_name\fP]
[\fB\-X\fP \fIattribute\fP[=\fIvalue\fP]]
[\fIprincipal\fP]
.ad b
.br
.SH DESCRIPTION
.I kinit
obtains and caches an initial ticket-granting ticket for
.IR principal .  
The typical default behavior is to acquire only
Kerberos 5 tickets.  However, if kinit was built with both 
Kerberos 4 support and with the default behavior of acquiring both
types of tickets, it will try to acquire both Kerberos 5 and Kerberos 4
by default.
Any documentation particular to Kerberos 4 does not apply if Kerberos 4
support was not built into kinit.
.SH OPTIONS
.TP
.B \-5
get Kerberos 5 tickets.  This overrides whatever the default built-in
behavior may be.  This option may be used with
.B \-4
.
.TP
.B \-4
get Kerberos 4 tickets.  This overrides whatever the default built-in
behavior may be.  This option is only available if kinit was built
with Kerberos 4 compatibility.  This option may be used with 
.B \-5
.
.TP
.B \-V
display verbose output.
.TP
\fB\-l\fP \fIlifetime\fP
requests a ticket with the lifetime
.IR lifetime .
The value for
.I lifetime
must be followed immediately by one of the following delimiters:
.sp
.nf
.in +.3i
\fBs\fP  seconds
\fBm\fP  minutes
\fBh\fP  hours
\fBd\fP  days
.in -.3i
.fi
.sp
as in "kinit -l 90m".  You cannot mix units; a value of `3h30m' will
result in an error.
.sp
If the
.B \-l
option is not specified, the default ticket lifetime (configured by each
site) is used.  Specifying a ticket lifetime longer than the maximum
ticket lifetime (configured by each site) results in a ticket with the
maximum lifetime.
.TP
\fB\-s\fP \fIstart_time\fP
requests a postdated ticket, valid starting at
.IR start_time .
Postdated tickets are issued with the
.I invalid
flag set, and need to be fed back to the kdc before use.
(Not applicable to Kerberos 4.)
.TP
\fB\-r\fP \fIrenewable_life\fP
requests renewable tickets, with a total lifetime of
.IR renewable_life .
The duration is in the same format as the
.B \-l
option, with the same delimiters.  (Not applicable to Kerberos 4.)
.TP
.B \-f
request forwardable tickets.  (Not applicable to Kerberos 4.)
.TP
.B \-F
do not request forwardable tickets.  (Not applicable to Kerberos 4.)
.TP
.B \-p
request proxiable tickets.  (Not applicable to Kerberos 4.)
.TP
.B \-P
do not request proxiable tickets.  (Not applicable to Kerberos 4.)
.TP
.B \-a
request tickets with the local address[es].  (Not applicable to Kerberos 4.)
.TP
.B \-A
request address-less tickets.  (Not applicable to Kerberos 4.)
.TP
.B \-v
requests that the ticket granting ticket in the cache (with the 
.I invalid
flag set) be passed to the kdc for validation.  If the ticket is within
its requested time range, the cache is replaced with the validated
ticket.  (Not applicable to Kerberos 4.)
.TP
.B \-R
requests renewal of the ticket-granting ticket.  Note that an expired
ticket cannot be renewed, even if the ticket is still within its
renewable life.  When using this option with Kerberos 4, the kdc must
support Kerberos 5 to Kerberos 4 ticket conversion.
.TP
\fB\-k\fP [\fB\-t\fP \fIkeytab_file\fP]
requests a host ticket, obtained from a key in the local host's
.I keytab
file.  The name and location of the keytab file may be specified with
the
.B \-t
.I keytab_file
option; otherwise the default name and location will be used.  When using
this option with Kerberos 4, the kdc must support Kerberos 5 to Kerberos 4
ticket conversion.
.TP
\fB\-c\fP \fIcache_name\fP
use
.I cache_name
as the Kerberos 5 credentials (ticket) cache name and location; if this 
option is not used, the default cache name and location are used.
.sp
The default credentials cache may vary between systems.  If the
.B KRB5CCNAME
environment variable is set, its value is used to name the default
ticket cache.  Any existing contents of the cache are destroyed by
.IR kinit .
(Note: The default name for Kerberos 4 comes from the
.B KRBTKFILE
environment variable.  This option does not apply to Kerberos 4.)
.TP
\fB\-S\fP \fIservice_name\fP
specify an alternate service name to use when
getting initial tickets.  (Applicable to Kerberos 5 or if using both
Kerberos 5 and Kerberos 4 with a kdc that supports Kerberos 5 to Kerberos 4
ticket conversion.)
.TP
\fB\-X\fP \fIattribute\fP[=\fIvalue\fP]
specify a pre\-authentication attribute and value to be passed to
pre\-authentication plugins.  The acceptable \fIattribute\fP and
\fIvalue\fP values vary from pre\-authentication plugin to plugin.
This option may be specified multiple times to specify multiple
attributes.  If no \fIvalue\fP is specified, it is assumed to be
"yes".
.sp
.nf
The following attributes are recognized by the OpenSSL pkinit
pre-authentication mechanism:
.in +.3i
\fBX509_user_identity\fP=\fIvalue\fP
   specify where to find user's X509 identity information
\fBX509_anchors\fP=\fIvalue\fP
   specify where to find trusted X509 anchor information
\fBflag_RSA_PROTOCOL\fP[=yes]
   specify use of RSA, rather than the default Diffie-Hellman protocol
.in -.3i
.fi
.sp
.SH ENVIRONMENT
.B Kinit
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
.TP
/etc/krb5.keytab
default location for the local host's
.B keytab
file.
.SH SEE ALSO
klist(1), kdestroy(1), kerberos(1)
