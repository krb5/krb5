.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1989,1991 by the Massachusetts Institute of Technology.
.\"
.\" Export of this software from the United States of America is assumed
.\"   to require a specific license from the United States Government.
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
.TH KRB.REALMS 5 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
krb.realms \- host to Kerberos realm translation file
.SH DESCRIPTION
.I krb.realms
provides a translation from a hostname to the Kerberos realm name for
the services provided by that host.
.PP
Each line of the translation file is in one of the following forms
(domain_name should be of the form .XXX.YYY, e.g. .LCS.MIT.EDU):
.nf
.in +5n
host_name kerberos_realm
domain_name kerberos_realm
.in -5n
.fi
If a hostname exactly matches the 
.I host_name
field in a line of the first
form, the corresponding realm is the realm of the host.
If a hostname does not match any 
.I host_name
in the file, but its
domain exactly matches the 
.I domain_name
field in a line of the second
form, the corresponding realm is the realm of the host.
.PP
If no translation entry applies, the host's realm is considered to be
the hostname's domain portion converted to upper case.
For example, the following file:
.sp
.nf
.in +1i
 .MIT.EDU ATHENA.MIT.EDU
 .MIT.EDU. ATHENA.MIT.EDU
 MIT.EDU ATHENA.MIT.EDU
 DODO.MIT.EDU SMS_TEST.MIT.EDU
 .UCSC.EDU CATS.UCSC.EDU
 .UCSC.EDU. CATS.UCSC.EDU
.in -1i
.fi
.sp
maps dodo.mit.edu into the SMS_TEST.MIT.EDU realm, all other hosts in
the MIT.EDU domain to the ATHENA.MIT.EDU realm, and all hosts in the
UCSC.EDU domain into the CATS.UCSC.EDU realm.  [The trailing dot is to
ensure that anchored domain names are properly matched.]
ucbvax.berkeley.edu would be mapped by the default rules to the
BERKELEY.EDU realm, while sage.lcs.mit.edu would be mapped to the
LCS.MIT.EDU realm.
.SH SEE ALSO
krb.conf(5)
