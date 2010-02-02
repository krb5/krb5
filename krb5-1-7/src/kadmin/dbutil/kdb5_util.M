.TH KDB5_UTIL 8
.SH NAME
kdb5_util \- Kerberos database maintainance utility
.SH SYNOPSIS
.B kdb5_util
[\fB\-r\fP\ \fIrealm\fP] [\fB\-d\fP\ \fIdbname\fP]
[\fB\-k\fP\ \fImkeytype\fP] [\fB\-M\fP\ \fImkeyname\fP]
[\fB\-kv\fP\ \fImkeyVNO\fP] 
[\fB\-sf\fP\ \fIstashfilename\fP]
[\fB\-m\fP]
.I command
.I [command_options]
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
.PP
Note that some KDB plugins may not support all
.B kdb5_util
commands.
.SH COMMAND-LINE OPTIONS
.TP
\fB\-r\fP\ \fIrealm\fP
specifies the Kerberos realm of the database; by default the realm
returned by
.IR krb5_default_local_realm (3)
is used.
.TP
\fB\-d\fP\ \fIdbname\fP
specifies the name under which the principal database is stored; by
default the database is that listed in
.IR kdc.conf (5).
The KADM5 policy database and lock file are also derived from this
value.
.TP
\fB\-k\fP\ \fImkeytype\fP
specifies the key type of the master key in the database; the default is
that given in
.IR kdc.conf .
.TP
\fB\-kv\fP\ \fImkeyVNO\fP
Specifies the version number of the master key in the database; the default is
1.  Note that 0 is not allowed.
.TP
\fB\-M\fP\ \fImkeyname\fP
principal name for the master key in the database; the default is
that given in
.IR kdc.conf .
.TP
.B \-m
specifies that the master database password should be read from the TTY
rather than fetched from a file on disk.
.TP
\fB\-sf\fP \fIstash_file\fP
specifies the stash file of the master database password.
.TP
\fB\-P\fP \fIpassword\fP
specifies the master database password.  This option is not recommended.
.SH COMMANDS
.TP
\fBcreate\fP [\fB\-s\fP]
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
\fBstash\fP [\fB\-f\fP\ \fIkeyfile\fP]
Stores the master principal's keys in a stash file.  The
.B \-f
argument can be used to override the keyfile specified at startup.
.TP
\fBdump\fP [\fB\-old\fP] [\fB\-b6\fP] [\fB\-b7\fP] [\fB\-ov\fP]
[\fB\-verbose\fP] [\fB\-mkey_convert\fP]
[\fB\-new_mkey_file\fP \fImkey_file\fP] [\fB\-rev\fP] [\fB\-recurse\fP]
[\fIfilename\fP [\fIprincipals...\fP]]
.br
Dumps the current Kerberos and KADM5 database into an ASCII file.  By
default, the database is dumped in current format, "kdb5_util
load_dumpversion 5".  If
.I filename
is not specified, or is the string "\-", the dump is sent to standard
output.  Options:
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
.B \-b7
causes the dump to be in the Kerberos 5 Beta 7 format ("kdb5_util load_dump version 4").  This was the dump format produced on releases prior to 1.2.2.
.TP
.B \-ov
causes the dump to be in
.I ovsec_adm_export
format.
.TP
.B \-verbose
causes the name of each principal and policy to be printed as it is
dumped.
.TP
.B \-mkey_convert
prompts for a new master key.  This new master key will be used to
re-encrypt the key data in the dumpfile.  The key data in the database
will not be changed.
.TP
.B \-new_mkey_file \fImkey_file\fP
the filename of a stash file.  The master key in this stash file will
be used to re-encrypt the key data in the dumpfile.  The key data in
the database will not be changed.
.TP
.B \-rev
dumps in reverse order.  This may recover principals that do not dump
normally, in cases where database corruption has occured.
.TP
.B \-recurse
causes the dump to walk the database recursively (btree only).  This
may recover principals that do not dump normally, in cases where
database corruption has occured.  In cases of such corruption, this
option will probably retrieve more principals than the \fB\-rev\fP
option will.
.RE
.TP
\fBload\fP [\fB\-old\fP] [\fB\-b6\fP] [\fB\-b7\fP] [\fB\-ov\fP] [\fB\-hash\fP]
[\fB\-verbose\fP] [\fB\-update\fP] \fIfilename dbname\fP
.br
Loads a database dump from the named file into the named database.
Unless the 
.B \-old
or 
.B \-b6
option is given, the format of the dump file is detected
automatically and handled as appropriate.  Unless the
.B \-update
option is given, 
.B load
creates a new database containing only the principals in the dump file,
overwriting the contents of any previously existing database.  Note that
when using the LDAP KDB plugin the
.B \-update
must be given.  Options:
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
.B \-b7
requires the database to be in the Kerberos 5 Beta 7 format ("kdb5_util
load_dump version 4").
.TP
.B \-ov
requires the database to be in
.I ovsec_adm_import
format.  Must be used with the
.B \-update
option.
.TP
.B \-hash
requires the database to be stored as a hash.  If this option is not
specified, the database will be stored as a btree.  This option
is not recommended, as databases stored in hash format are known to
corrupt data and lose principals.
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
.RE
.TP
\fBark\fP
Adds a random key.
.TP
\fBadd_mkey\fP [\fB\-e etype\fP] [\fB\-s\fP] 
Adds a new master key to the K/M (master key) principal.  Existing master keys will remain.
The
.B \-e etype
option allows specification of the enctype of the new master key.  The
.B \-s
option stashes the new master key in a local stash file which will be created if it doesn't already exist.
.TP
\fBuse_mkey\fP \fImkeyVNO [\fBtime\fP]
Sets the activation time of the master key specified by 
.B mkeyVNO.
Once a master key is active (i.e. its activation time has been reached) it will then be used to encrypt principal keys either when the principal keys change, are newly created or when the update_princ_encryption command is run.  If the
.B time 
argument is provided then that will be the activation time otherwise the current time is used by default.  The format of the optional
.B time 
argument is that specified in the Time Formats section of the kadmin man page.
.TP
\fBlist_mkeys\fP
List all master keys from most recent to earliest in K/M principal. The output will show the KVNO, enctype and salt for each mkey similar to kadmin getprinc output.  A * following an mkey denotes the currently active master key. 
.TP
\fBpurge_mkeys\fP [\fB-f\fP] [\fB-n\fP] [\fB-v\fP]
Delete master keys from the K/M principal that are not used to protect any principals.  This command can be used to remove old master keys from a K/M principal once all principal keys are protected by a newer master key.
.TP
.B \-f
does not prompt user.
.TP
.B \-n
do a dry run, shows master keys that would be purged, does not actually purge any keys.
.TP
.B \-v
verbose output.
.TP
\fBupdate_princ_encryption\fP [\fB\-f\fP] [\fB\-n\fP] [\fB\-v\fP] [\fBprinc\-pattern\fP]
Update all principal records (or only those matching the
.B princ\-pattern
glob pattern) to re-encrypt the key data using the active
database master key, if they are encrypted using older versions,
and give a count at the end of the number of principals updated.
If the
.B \-f
option is not given, ask for confirmation before starting to make
changes.  The
.B \-v
option causes each principal processed (each one matching the pattern)
to be listed, and an indication given as to whether it needed updating
or not.
The
.B \-n
option causes the actions not to be taken, only the normal or verbose
status messages displayed; this implies
.B \-f
since no database changes will be performed and thus there's little
reason to seek confirmation.
.SH SEE ALSO
kadmin(8)
