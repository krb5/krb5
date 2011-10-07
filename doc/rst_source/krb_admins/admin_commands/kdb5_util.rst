.. _kdb5_util(8):

kdb5_util
==========

SYNOPSIS
---------------

.. _kdb5_util_synopsys:
       
**kdb5_util** 
            [**-r** *realm*] 
            [**-d** *dbname*] 
            [**-k** *mkeytype*] 
            [**-M** *mkeyname*] 
            [**-kv** *mkeyVNO*] 
            [**-sf** *stashfilename*] 
            [**-m**] 
            *command* [*command_options*]

.. _kdb5_util_synopsys_end:

DESCRIPTION
---------------
       
*kdb5_util*  allows an administrator to perform low-level maintenance procedures on the Kerberos and KADM5 database.  
Databases can be created, destroyed, and dumped to and loaded from ASCII files.  
Additionally, *kdb5_util* can create a Kerberos master key stash file.  
*kdb5_util* subsumes the functionality of and makes obsolete the previous database maintenance programs kdb5_create, kdb5_edit, kdb5_destroy, and kdb5_stash.

When *kdb5_util* is run, it attempts to acquire the master key and open the database.  However, execution continues regardless of whether or not
*kdb5_util* successfully opens the database, because the database may not exist yet or the stash file may be corrupt.

Note that some KDB plugins may not support all *kdb5_util* commands.

COMMAND-LINE OPTIONS
----------------------
       
.. _kdb5_util_options:

       **-r** *realm*
              specifies the Kerberos realm of the database.

       **-d** *dbname*
              specifies the name under which the principal database is stored; by default the database is that listed in :ref:`kdc.conf`.   
              The  KADM5  policy database and lock file are also derived from this value.

       **-k** *mkeytype*
              specifies the key type of the master key in the database; the default is that given in :ref:`kdc.conf`.

       **-kv** *mkeyVNO*
              Specifies the version number of the master key in the database; the default is 1.  Note that 0 is not allowed.

       **-M** *mkeyname*
              principal name for the master key in the database; the default is that given in :ref:`kdc.conf`.

       **-m**
              specifies that the master database password should be read from the TTY rather than fetched from a file on disk.

       **-sf** *stash_file*
              specifies the stash file of the master database password.

       **-P** *password*
              specifies the master database password.  This option is not recommended.

.. _kdb5_util_options_end:

COMMANDS
---------------
       
.. _kdb5_util_create:

       **create** [**-s**]
              Creates a new database.  If the *-s* option is specified, the stash file is also created.  This command fails if the database already exists.
              If the command is successful, the database is opened just as if it had already existed when the program was first run.

.. _kdb5_util_create_end:

.. _kdb5_util_destroy:

       **destroy** [**-f**]
              Destroys the database, first overwriting the disk sectors and then unlinking the files, after prompting the user for confirmation.
              With the *-f* argument, does not prompt the user.

.. _kdb5_util_destroy_end:

.. _kdb5_util_stash:

       **stash** [**-f** *keyfile*]
              Stores the master principal's keys in a stash file.  The *-f* argument can be used to override the *keyfile* specified at startup.

.. _kdb5_util_stash_end:

.. _kdb5_util_dump:

       **dump** [**-old|-b6|-b7|-ov|-r13**] [**-verbose**] [**-mkey_convert**] [**-new_mkey_file** *mkey_file*] [**-rev**] [**-recurse**] [*filename* [*principals*...]]
              Dumps the current Kerberos and KADM5 database into an ASCII file.  By default, the database is dumped in current format, "*kdb5_util*
              load_dump version 6".  If filename is not specified, or is the string "-", the dump is sent to standard output.  Options:

              **-old**
                     causes the dump to be in the Kerberos 5 Beta 5 and earlier dump format ("kdb5_edit load_dump version 2.0").

              **-b6**
                     causes the dump to be in the Kerberos 5 Beta 6 format ("kdb5_edit load_dump version 3.0").

              **-b7**
                     causes the dump to be in the Kerberos 5 Beta 7 format ("*kdb5_util* load_dump version 4").   
                     This  was  the  dump  format  produced  on releases prior to 1.2.2.

              **-ov**
                     causes the dump to be in *ovsec_adm_export* format.

              **-r13**
                     causes the dump to be in the Kerberos 5 1.3 format ("*kdb5_util* load_dump version 5").  
                     This was the dump format produced on releases prior to 1.8.

              **-verbose**
                     causes the name of each principal and policy to be printed as it is dumped.

              **-mkey_convert**
                     prompts for a new master key.  This new master key will be used to re-encrypt the key data in the dumpfile.
                     The key data in the database will not be changed.

              **-new_mkey_file** *mkey_file*
                     the filename of a stash file.  The master key in this stash file will be used to re-encrypt the key data in the dumpfile.
                     The key data in the database will not be changed.

              **-rev**
                     dumps in reverse order.  This may recover principals that do not dump normally, in cases where database corruption has occured.

              **-recurse**
                     causes the dump to walk the database recursively (btree only).  This may recover principals that do not dump normally,
                     in cases where database corruption has occured.
                     In  cases  of such corruption, this option will probably retrieve more principals than the *-rev* option will.

.. _kdb5_util_dump_end:

.. _kdb5_util_load:

       **load** [**-old|-b6|-b7|-ov|-r13**] [**-hash**] [**-verbose**] [**-update**] *filename dbname*
              Loads a database dump from the named file into the named database.  
              Unless the *-old* or *-b6* option is given, the format of the dump file is detected automatically and handled as appropriate.
              Unless the *-update* option is given, load creates a new database containing only the principals in the dump file,
              overwriting the contents of any previously existing database.
              Note that when using the LDAP KDB plugin the *-update* must be given.  Options:

              **-old**
                     requires the database to be in the Kerberos 5 Beta 5 and earlier format ("kdb5_edit load_dump version 2.0").

              **-b6**
                     requires the database to be in the Kerberos 5 Beta 6 format ("kdb5_edit load_dump version 3.0").

              **-b7**
                     requires the database to be in the Kerberos 5 Beta 7 format ("*kdb5_util* load_dump version 4").

              **-ov**
                     requires the database to be in ovsec_adm_import format.  Must be used with the *-update* option.

              **-hash**
                     requires the database to be stored as a hash.  If this option is not specified, the database will be stored as a btree.
                     This option is not recommended, as databases stored in hash format are known to corrupt data and lose principals.

              **-verbose**
                     causes the name of each principal and policy to be printed as it is dumped.

              **-update**
                     records from the dump file are added to or updated in the existing database.
                     (This is useful in conjunction with an *ovsec_adm_export* format dump if you want to preserve per-principal policy information,
                     since the current default format does not contain this data.)
                     Otherwise, a new database is created containing only what is in the dump file and the old one destroyed upon successful completion.

              *dbname* is required and overrides the value specified on the command line or the default.

.. _kdb5_util_load_end:

       **ark**
              Adds a random key.

       **add_mkey** [**-e** *etype*] [**-s**]
              Adds a new master key to the *K/M* (master key) principal.  Existing master keys will remain.
              The *-e etype* option allows specification of the enctype of the new master key.
              The *-s* option stashes the new master key in a local stash file which will be created if it doesn't already exist.

       **use_mkey** *mkeyVNO* [*time*]
              Sets the activation time of the master key specified by *mkeyVNO*.
              Once a master key is active (i.e. its activation time has been reached) it will then be used to encrypt principal keys either when
              the principal keys change, are newly created or when the *update_princ_encryption* command is run.
              If the time argument is provided then that will be the activation time otherwise the current time is used by default.
              The format of the optional time argument is that specified in the *Time Formats* section of the kadmin man page.

       **list_mkeys**
              List all master keys from most recent to earliest in *K/M* principal.
              The output will show the kvno, enctype and salt for each mkey similar to kadmin getprinc output.
              A \* following an mkey denotes the currently active master key.

       **purge_mkeys** [**-f**] [**-n**] [**-v**]
              Delete master keys from the *K/M* principal that are not used to protect any principals.
              This command can be used to remove old master keys from a *K/M* principal once all principal keys are protected by a newer master key.

              **-f**     
                     does not prompt user.

              **-n**
                     do a dry run, shows master keys that would be purged, does not actually purge any keys.

              **-v**
                     verbose output.

       **update_princ_encryption** [**-f**] [**-n**] [**-v**] [*princ-pattern*]
              Update all principal records (or only those matching the princ-pattern glob pattern)
              to re-encrypt the key data using the active database master key, if they are encrypted using older versions,
              and give a count at the end of the number of principals updated.
              If the *-f* option is not given, ask for confirmation before starting to make changes.
              The *-v* option causes each principal processed (each one matching the pattern) to be listed,
              and an indication given as to whether it needed updating or not.
              The *-n* option causes the actions not to be taken, only the normal or verbose status messages displayed;
              this implies *-f* since no database changes will be performed and thus there's little reason to seek confirmation.

SEE ALSO
---------------
       
kadmin(8)


