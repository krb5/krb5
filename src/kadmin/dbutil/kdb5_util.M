KDB5_UTIL(8)

NAME
	kdb5_util - Kerberos database maintainance utility

SYNOPSIS
	kdb5_util [-d dbpathname ] [-r realmname] [-R request ]
		  [-s scriptfile] [-k enctype] [-M mkeyname] 
		  [-f stashfile]

DESCRIPTION
	kdb5_util allows an administrator to perform low-level
	maintainance procedures on the Kerberos and KADM5 database.
	Databases can be created, destroyed, and dumped to and loaded
	from ASCII files.  Additionally, kdb5_util can create a
	Kerberos master key stash file.  kdb5_util subsumes the
	functionality of and makes obsolete the previous database
	maintainance programs kdb5_create, kdb5_edit, kdb5_destroy,
	and kdb5_stash.

	When the program is first run, it attempts to acquire the
	master key and open the database.  Execution continues whether
	or not it is successful, however, because the database may not
	exist yet or the stash file may be corrupt.  Commands can be
	issued using one of three mechanisms.  If a single command is
	supplied using the request argument, then that single command
	is processed and execution ceases.  If a script file is
	provided using the -s script argument, then commands are read
	from this file until either an error occurs or an end of file
	is detected.  Finally, if neither a command or a script is
	specified, the invoker is placed into a shell-like command
	loop, from which commands may be executed.

	The -r realm option specifies the realm of the database; by
	default the realm returned by krb5_default_local_realm(3) is
	used.

	The -d dbname option specifies the name under which the
	principal database is stored; by default the database is
	controlled by kdc.conf.  The KADM5 policy database and lock
	file are also derived from this value.

	The -k keytype option specifies the key type of the master key
	in the database; the default is controlled by kdc.conf.

	The -f stashfile option specifies the filename of the stashed
	V5 master key. The default is controlled by kdc.conf and is
	typically <krb5-prefix>/lib/krb5kdc/.k5.REALMNAME. (In
	previous releases, this would have been /.k5.REALMNAME.)

	The -M mkeyname option specifies the principal name for the
	master key in the database; the default is controlled by
	kdc.conf.

	The -m option specifies that the master database password
	should be fetched from the keyboard rather than from a file on
	disk.

AVAILABLE COMMANDS
	create_db [-s]

	Alias: create.  Creates a new database.  If the -s option is
	specified, the stash file is also created.  This command fails
	if the database already exists.  If the command is successful,
	the database is opened just as if it had already existed when
	the program was first run.

	destroy_db [-f]

	Alias: destroy.  Destroys the database, first overwriting the
	disk sectors and then unlinking the files, after prompting the
	user for confirmation.  With the -f argument, does not prompt
	the user.

	stash_mkey [-f keyfile]

	Alias: stash.  Stores the master principal's keys in a stash
	file.  The -f argument can be used to override the keyfile
	specified at startup.

	dump_db [-old] [-b6] [-verbose] [filename [principals...]]

	Alias: ddb.  Dumps the current Kerberos and KADM5 database
	into an ASCII file.  By default, the database is dumped in
	current format, "kdb5_util load_dump version 4".  The -b6
	argument causes the dump to be in the Kerberos 5 Beta 6 format
	("kdb5_edit load_dump version 3.0").  The -old argument causes
	the dump to be in the Kerberos 5 Beta 5 and earlier dump
	format ("kdb5_edit load_dump version 2.0").  The -verbose
	option causes the name of each principal and policy to be
	printed as it is dumped.

	load_db [-old] [-b6] [-verbose] [-update] filename dbname 
		[admin_dbname]

	Alias: lddb.  Loads a database dump from the named file into
	the named database.  The -old and -b6 options require the dump
	to be in the specified format (see dump_db); otherwise, the
	format of the dump file is detected automatically and handled
	as appropriate.  If the -update argument is specified, records
	from the dump file are merely added to or updated in the
	existing database; otherwise, a new database is created
	containing only what is in the dump file and the old one
	destroyed on a successful completion.  The dbname argument is
	required (XXX probably shouldn't be) and overrides the value
	specified on the command line or the default.  The
	admin_dbname is optional and is derived from dbname if not
	specified.

	dump_v4db [filename]

	Alias: d4db.  Dumps the current database into the Kerberos 4
	database dump format.

	load_v4db [-d v5dbpathname] [-t] [-n] [-r realmname] [-K]
		  [-k enctype] [-M mkeyname] -f inputfile

	Alias: lddb4.  Loads a Kerberos 4 database dump file.  XXX Not
	sure what all the arguments mean.

SEE ALSO
	kadm5_export(8), kadm5_import(8)
