.\" admin/aname/kdb5_anadd.M
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
.\" permission.  M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" "
.so man1/header.doc
.TH KDB5_ANADD 8 \*h
.SH NAME
kdb5_anadd \- manipulate aname/lname translation database
.SH SYNOPSIS
.B kdb5_anadd
[
.B \-a
] [
.B \-n
.I dbname
] kerberos_principal local_name
.br
.B kdb5_anadd \-d
[
.B \-n
.I dbname
] kerberos_principal 
.br
.SH DESCRIPTION
.I kdb5_anadd
is a primitive tool for manipulating a database which maps
kerberos principals into user accounts on the local machine.  By
default, Kerberos assumes that a kerberos principal
"username@LOCALREALM" maps into the account "username" on the local
machine.  However, this assumption is not always true.

.PP
In order accomodate systems which have local usernames which are not the
same as Kerberos principals, the system administrator can use 
.I krb5_anadd
to set up mappings between a kerberos name and a local account name.  (If
this database is established using 
.Ikrb5_anadd, 
then Kerberos will not do
the default mapping; you will have to specify each mapping between a
Kerberos principal and username manually).

.PP
For example, the following mapping can be established by
.Ikrb5_anadd: 
"joechen@ATHENA.MIT.EDU" maps to "joe" by using the command:

.PP
krb5_adadd jochen@ATHENA.MIT.EDU joe

.PP
After this command, if joechen@ATHENA.MIT.EDU tries to do an
authenticated rlogin to the account "joe" on that machine, the Kerberos
access control mechanism will allow the login, since
joechen@ATHENA.MIT.EDU is considered to be the local user "joe".

.PP
The \fB\-d\fP option deletes translations from the
database; after execution the principal named by 
.I pname
will not translate to any local name.
.PP
For both uses, the
.B \-n
.I dbname
option specifies the name of the database which holds the translation;
the default database is DEFAULT_LNAME_FILENAME (usually /krb5/aname).
.SH SEE ALSO
krb5(3)
krb5_aname_to_localname (3)
.SH BUGS
The mapping is many-to-one, not many-to-many.


