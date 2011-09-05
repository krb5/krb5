.TH .K5LOGIN 5
.SH NAME
\&.k5identity \- Kerberos V5 client principal selection rules
.SH DESCRIPTION
The \fB.k5identity\fP file, which resides in a user's home directory,
contains a list of rules for selecting a client principals based on
the server being accessed.  These rules are used to choose a
credential cache within the cache collection when possible.
.PP
Blank lines and lines beginning with '#' are ignored.  Each line has
the form:
.PP
.RS
\fIprincipal\fP \fIfield\fP=\fIvalue\fP ...
.RE
.PP
If the server principal meets all of the \fIfield\fP constraints, then
\fIprincipal\fP is chosen as the client principal.  The following
fields are recognized:
.TP
.B realm
If the realm of the server principal is known, it is matched against
\fIvalue\fP, which may be a pattern using shell wildcards.  For
host-based server principals, the realm will generally only be known
if there is a domain_realm section in krb5.conf with a mapping for the
hostname.
.TP
.B service
If the server principal is a host-based principal, its service
component is matched against \fIvalue\fP, which may be a pattern using
shell wildcards.
.TP
.B host
If the server principal is a host-based principal, its hostname
component is converted to lower case and matched against \fIvalue\fP,
which may be a pattern using shell wildcards.
.PP
If the server principal matches the constraints of multiple lines in
the \fB.k5identity\fP file, the principal from the first matching line
is used.  If no line matches, credentials will be selected some other
way, such as the realm heuristic or the current primary cache.
.SH EXAMPLE
The following example \fB.k5identity\fP file selects the client
principal alice@KRBTEST.COM if the server principal is within that
realm, the principal alice/root@EXAMPLE.COM if the server host is
within a servers subdomain, and the principal alice/mail@EXAMPLE.COM
when accessing the IMAP service on mail.example.com.
.PP
.RS
.nf
alice@KRBTEST.COM       realm=KRBTEST.COM
alice/root@EXAMPLE.COM  host=*.servers.example.com
alice/mail@EXAMPLE.COM  host=mail.example.com service=imap
.fi
.RE
.SH SEE ALSO
kerberos(1), krb5.conf(5)
