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
[\fB\-V\fP]
[\fB\-l\fP \fIlifetime\fP] [\fB\-s\fP \fIstart_time\fP]
[\fB\-r\fP \fIrenewable_life\fP]
[\fB\-p\fP | \fB\-P\fP]
[\fB\-f\fP | \fB\-F\fP]
[\fB\-a\fP]
[\fB\-A\fP]
[\fB\-C\fP]
[\fB\-E\fP]
[\fB\-v\fP] [\fB\-R\fP]
[\fB\-k\fP [\fB\-t\fP \fIkeytab_file\fP]] [\fB\-c\fP \fIcache_name\fP]
[\fB\-n\fP]
[\fB\-S\fP \fIservice_name\fP][\fB\-T\fP \fIarmor_ccache\fP]
[\fB\-X\fP \fIattribute\fP[=\fIvalue\fP]]
[\fIprincipal\fP]
.ad b
.br
.SH DESCRIPTION
.I kinit
obtains and caches an initial ticket-granting ticket for
.IR principal .  
.SH OPTIONS
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
.TP
\fB\-r\fP \fIrenewable_life\fP
requests renewable tickets, with a total lifetime of
.IR renewable_life .
The duration is in the same format as the
.B \-l
option, with the same delimiters.
.TP
.B \-f
request forwardable tickets.
.TP
.B \-F
do not request forwardable tickets.
.TP
.B \-p
request proxiable tickets.
.TP
.B \-P
do not request proxiable tickets.
.TP
.B \-a
request tickets with the local address[es].
.TP
.B \-A
request address-less tickets.
.TP
.B \-C
requests canonicalization of the principal name.
.TP
.B \-E
treats the principal name as an enterprise name.
.TP
.B \-v
requests that the ticket granting ticket in the cache (with the 
.I invalid
flag set) be passed to the kdc for validation.  If the ticket is within
its requested time range, the cache is replaced with the validated
ticket.
.TP
.B \-R
requests renewal of the ticket-granting ticket.  Note that an expired
ticket cannot be renewed, even if the ticket is still within its
renewable life.
.TP
\fB\-k\fP [\fB\-t\fP \fIkeytab_file\fP]
requests a ticket, obtained from a key in the local host's
.I keytab
file.  The name and location of the keytab file may be specified with
the
.B \-t
.I keytab_file
option; otherwise the default name and location will be used.  By
default a host ticket is requested but any principal may be
specified. On a KDC, the special keytab location
.B KDB:
can be used to indicate that kinit should open the KDC database and
look up the key directly.  This permits an administrator to obtain
tickets as any principal that supports password-based authentication.
.TP
\fB-n\fP
Requests anonymous processing.  Two types of anonymous principals are
supported.  For fully anonymous Kerberos, configure pkinit on the KDC
and configure
.I pkinit_anchors
in the client's krb5.conf.  Then use the
.B -n
option with a principal of the form
.I @REALM
(an empty principal name followed by the at-sign and a realm name).
If permitted by the KDC, an anonymous ticket will be returned.
A second form of anonymous tickets is supported; these realm-exposed
tickets hide the identity of the client but not the client's realm.
For this mode, use
.B kinit -n
with a normal principal name.  If supported by the KDC, the principal
(but not realm) will be replaced by the anonymous principal.
As of release 1.8, the MIT Kerberos KDC only supports fully anonymous
operation.
.TP
\fB\-T\fP \fIarmor_ccache\fP
Specifies the name of a credential cache that already contains a
ticket.  If supported by the KDC, This ccache will be used to armor
the request so that an attacker would have to know both the key of the
armor ticket and the key of the principal used for authentication in
order to attack the request. Armoring also makes sure that the
response from the KDC is not modified in transit.
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
.TP
\fB\-S\fP \fIservice_name\fP
specify an alternate service name to use when
getting initial tickets.
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
klist(1), kdestroy(1), kerberos(1)
