.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1990 by the Massachusetts Institute of Technology.
.\"
.\" For copying and distribution information, please see the file
.\" <krb5/copyright.h>.
.\"
.TH KDB5_ANADD 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kdb5_anadd \- manipulate aname/lname translation database
.SH SYNOPSIS
.B kdb5_anadd
[
.B \-a
] [
.B \-n
.I dbname
] pname lname
.br
.B kdb5_anadd \-d
[
.B \-n
.I dbname
] pname
.br
.SH DESCRIPTION
.I kdb5_anadd
is a primitive tool for manipulating the authentication name (aname) to
local name (lname) translation database.
.PP
The first use described above is for entering new translations or
changing existing translations from anames to lnames.
After execution, the function
.IR krb5_aname_to_localname (3)
with its first argument passed as a principal with text representation of
.I pname
will fill in
.I lname
as the translation.
.PP
The second use described above is for deleting translations from the
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
.SH BUGS
The mapping is many-to-one, not many-to-many.
