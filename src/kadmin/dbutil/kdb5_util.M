.TH KDB5_UTIL 8
.SH NAME
kdb5_util \- Kerberos database maintainance utility
.SH SYNOPSIS
.B kdb5_util
.I command
[\fB\-r\fP \fIrealm\fP] [\fB\-d\fP \fIdbname\fP]
[\fB\-k\fP \fImkeytype\fP] [\fB\-M\fP \fImkeyname\fP]
[\fB\-m\fP]
.I command_options
.SH DESCRIPTION
.B kdb5_util
allows an administrator to perform low-level maintainance procedures on
the Kerberos and KADM5 database.  Databases can be created, destroyed,
and dumped to and loaded from
.SM ASCII
files.  Additionally,
.B kdb5_util
can create a Kerberos master key stash file.
.B kdb5_util
subsumes the functionality of and makes obsolete the previous database
maintainance programs
.BR kdb5_create ,
.BR kdb5_edit ,
.BR kdb5_destroy ,
and
.BR kdb5_stash .
.PP
When
.B kdb5_util
is run, it attempts to acquire the master key and open the database.
However, execution continues regardless of whether or not
.B kdb5_util
successfully opens the database, because the database may not exist yet
or the stash file may be corrupt.
.SH COMMAND-LINE OPTIONS
.TP
\fB\-r\fP \fIrealm\fP
specifies the Kerberos realm of the database; by default the realm
returned by
.IR krb5_default_local_realm (3)
is used.
.TP
\fB-d\fP \fIdbname\fP
specifies the name under which the principal database is stored; by
default the database is that listed in
.IR kdc.conf (5).
The KADM5 policy database and lock file are also derived from this
value.
.TP
\fB\-k\fP \fImkeytype\fP
specifies the key type of the master key in the database; the default is
that given in
.IR kdc.conf .
.TP
\fB\-M\fP \fImkeyname\fP
principal name for the master key in the database; the default is
that given in
.IR kdc.conf .
.TP
.B \-m
specifies that the master database password should be read from the TTY
rather than fetched from a file on disk.
.SH COMMANDS
.TP
\fBcreate\fP [\fB-s\fP]
Creates a new database.  If the
.B \-s
option is specified, the stash file is also created.  This command fails
if the database already exists.  If the command is successful, the
database is opened just as if it had already existed when the program
was first run.
.TP
\fBdestroy\fP [\fB\-f\fP]
Destroys the database, first overwriting the disk sectors and then
unlinking the files, after prompting the user for confirmation.  With
the
.B \-f
argument, does not prompt the user.
.TP
\fBstash\fP [\fB\-f\fP \fIkeyfile\fP]
Stores the master principal's keys in a stash file.  The
.B \-f
argument can be used to override the keyfile specified at startup.
.TP
\fBdump\fP [\fB\-old\fP] [\fB\-b6\fP] [\fB\-ov\fP] [\fB-verbose\fP] [\fIfilename\fP [\fIprincipals...\fP]]
Dumps the current Kerberos and KADM5 database into an ASCII file.  By
default, the database is dumped in current format, "kdb5_util
load_dumpversion 4".  Options:
.RS
.TP
.B \-old
causes the dump to be in the Kerberos 5 Beta 5 and earlier dump format
("kdb5_edit load_dump version 2.0").
.TP
.B \-b6
causes the dump to be in the Kerberos 5 Beta 6 format ("kdb5_edit
load_dump version 3.0").
.TP
.B \-ov
causes the dump to be in
.I ovsec_adm_export
format.
.TP
.B \-verbose
causes the name of each principal and policy to be printed as it is
dumped.
.RE
.TP
\fBload\fP [\fB\-old\fP] [\fB\-b6\fP] [\fB\-ov\fP] [\fB-verbose\fP] [\fB-update\fP] \fIfilename dbname\fP [\fIadmin_dbname\fP]
Loads a database dump from the named file into the named database.
Unless the 
.B \-old
or 
.B \-b6
option is givnen, the format of the dump file is detected
automatically and handled as appropriate.  Unless the
.B \-update
option is given, 
.B load
creates a new database containing only the principals in the dump file,
overwriting the contents of any previously existing database.  Options:
.RS
.TP
.B \-old
requires the database to be in the Kerberos 5 Beta 5 and earlier format
("kdb5_edit load_dump version 2.0").
.TP
.B \-b6
requires the database to be in the Kerberos 5 Beta 6 format ("kdb5_edit
load_dump version 3.0").
.TP
.B \-ov
requires the database to be in
.I ovsec_adm_import
format.  Must be used with the
.B \-update
option.
.TP
.B \-verbose
causes the name of each principal and policy to be printed as it is
dumped.
.TP
.B \-update
records from the dump file are added to or updated in the existing
database; otherwise, a new database is created containing only what is
in the dump file and the old one destroyed upon successful completion.
.TP
.B dbname
is required and overrides the value specified on the command line or the
default.
.TP
.B admin_dbname
is optional and is derived from
.B dbname
if not specified.
.RE
.TP
\fBdump_v4\fP [\fIfilename\fP]
Dumps the current database into the Kerberos 4 database dump format.
.TP
\fBload_v4\fP [\fB\-t\fP] [\fB-n\fP] [\fB\-K\fP] [\fB-f\fP] \fIinputfile\fP
Loads a Kerberos 4 database dump file.
.SH SEE ALSO
kadmin(8)
