.\" $Source$
.\" $Author$
.\" $Id$
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
.\" 
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
