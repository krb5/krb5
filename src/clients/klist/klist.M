.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
.\"
.TH KLIST 1 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
klist \- list cached Kerberos tickets
.SH SYNOPSIS
.B klist
[
.B \-c
.I cachename
]
.br
.SH DESCRIPTION
.I klist
will list the primary principal and Kerberos tickets held in the default
credentials cache, or in the cache
.I cachename
if the
.B \-c
option is used.

The default credentials cache may vary between systems; however, if the
.B KRB5CCNAME
environment variable is set, its value is used to name the default
ticket cache.
.SH FILES
.TP 2i
.TP
/tmp/krb5cc_[uid]
as the normal default credentials cache ([uid] is the decimal UID of the user).
.SH SEE ALSO
kinit(1), kdestroy(1), krb5(3)
.SH BUGS
Does not display srvtabs yet.

Does not list ticket options or lifetimes.
