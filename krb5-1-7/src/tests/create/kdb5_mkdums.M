.\" tests/create/kdb5_mkdums.M
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
.\" 
.\"
.TH KDB5_MKDUMS 8
.SH NAME
kdb5_mkdums \- create a new Kerberos V5 principal database
.SH SYNOPSIS
.B kdb5_mkdums
.B \-n
.I number
.B \-p
.I prefix
[
.B \-D
.I depth
] [
.B \-r
.I realm
] [
.B \-d
.I dbname
] [
.B \-k
.I keytype
] [
.B \-M
.I mkeyname
] [
.B \-e
.I enctype
] [
.B \-m
]
.br
.SH DESCRIPTION
.I kdb5_mkdums
is used to create many test entries in a Kerberos version 5 principal
database. 
Each entry is created with a known password, for later verification.
.I kdb5_verify
can be used to verify that the entries were stored correctly in the
database and can be retrieved.
.I kdc5_hammer
can be used to make repeated ticket requests of the KDC for principals
created via
.I kdb5_mkdums
in order to ``stress test'' the KDC.
.PP
The
.B \-p
.I prefix
argument specifies the prefix name for each principal to be created.
The current number and depth will be appended to the prefix.
.PP
The
.B \-n
.I num_to_create
argument specifies the number of principals to create (at each depth).
.PP
The
.B \-D
.I depth
option specifies the maximum number of components a principal should
have; the default depth is 1.
.PP
The
.B \-r
.I realm
option specifies the realm in which the entreis should be created;
by default the realm returned by
.IR krb5_default_local_realm (3)
is used.
.PP
The
.B \-d
.I dbname
option specifies the name under which the principal database is to be
created; by default the database is in DEFAULT_DBM_FILE (normally
/krb5/principal).
.PP
The
.B \-k
.I keytype
option specifies the key type (as an ascii representation of a decimal
number) of the master key in the database; the default is KEYTYPE_DES.
.PP
The
.B \-M
.I mkeyname
option specifies the principal name for the master key in the database;
the default is KRB5_KDB_M_NAME (usually "K/M" in the KDC's realm).
.PP
The
.B \-e
.I enctype
option specifies the encryption type (as an ascii representation of a decimal
number) to be used when placing entries in
the database; the default is the default encryption type for the master
keytype.
.SH EXAMPLE
.I
kdb5_mkdums -p test -n 2 -D 3
.R
will create the following principals, each with their printed names as
passwords:
.nf
.in +1i
test1-DEPTH-1@FOO.MIT.EDU
test2-DEPTH-1@FOO.MIT.EDU
test1-DEPTH-1/test1-DEPTH-2@FOO.MIT.EDU
test2-DEPTH-1/test2-DEPTH-2@FOO.MIT.EDU
test1-DEPTH-1/test1-DEPTH-2/test1-DEPTH-3@FOO.MIT.EDU
test2-DEPTH-1/test2-DEPTH-2/test2-DEPTH-3@FOO.MIT.EDU
.in -1i
.fi
.SH BUGS
Should be do something intelligent about testing fields other than the
password.
.SH AUTHOR
Jon Rochlis, MIT Network Services
