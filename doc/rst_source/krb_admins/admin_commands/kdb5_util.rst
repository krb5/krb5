.. _kdb5_util(8):

kdb5_util
=========

SYNOPSIS
--------

.. _kdb5_util_synopsis:

**kdb5_util**
[**-r** *realm*]
[**-d** *dbname*]
[**-k** *mkeytype*]
[**-M** *mkeyname*]
[**-kv** *mkeyVNO*]
[**-sf** *stashfilename*]
[**-m**]
*command* [*command_options*]

.. _kdb5_util_synopsis_end:

DESCRIPTION
-----------

kdb5_util allows an administrator to perform maintenance procedures on
the KDC database.  Databases can be created, destroyed, and dumped to
or loaded from ASCII files.  kdb5_util can create a Kerberos master
key stash file or perform live rollover of the master key.

When kdb5_util is run, it attempts to acquire the master key and open
the database.  However, execution continues regardless of whether or
not kdb5_util successfully opens the database, because the database
may not exist yet or the stash file may be corrupt.

Note that some KDC database modules may not support all kdb5_util
commands.


COMMAND-LINE OPTIONS
--------------------

.. _kdb5_util_options:

**-r** *realm*
    specifies the Kerberos realm of the database.

**-d** *dbname*
    specifies the name under which the principal database is stored;
    by default the database is that listed in :ref:`kdc.conf(5)`.  The
    password policy database and lock files are also derived from this
    value.

**-k** *mkeytype*
    specifies the key type of the master key in the database.  The
    default is given by the **master_key_type** variable in
    :ref:`kdc.conf(5)`.

**-kv** *mkeyVNO*
    Specifies the version number of the master key in the database;
    the default is 1.  Note that 0 is not allowed.

**-M** *mkeyname*
    principal name for the master key in the database.  If not
    specified, the name is determined by the **master_key_name**
    variable in :ref:`kdc.conf(5)`.

**-m**
    specifies that the master database password should be read from
    the keyboard rather than fetched from a file on disk.

**-sf** *stash_file*
    specifies the stash filename of the master database password.  If
    not specified, the filename is determined by the
    **key_stash_file** variable in :ref:`kdc.conf(5)`.

**-P** *password*
    specifies the master database password.  Using this option may
    expose the password to other users on the system via the process
    list.

.. _kdb5_util_options_end:


COMMANDS
--------

create
~~~~~~

.. _kdb5_util_create:

    **create** [**-s**]

Creates a new database.  If the **-s** option is specified, the stash
file is also created.  This command fails if the database already
exists.  If the command is successful, the database is opened just as
if it had already existed when the program was first run.

.. _kdb5_util_create_end:

destroy
~~~~~~~

.. _kdb5_util_destroy:

    **destroy** [**-f**]

Destroys the database, first overwriting the disk sectors and then
unlinking the files, after prompting the user for confirmation.  With
the **-f** argument, does not prompt the user.

.. _kdb5_util_destroy_end:

stash
~~~~~

.. _kdb5_util_stash:

    **stash** [**-f** *keyfile*]

Stores the master principal's keys in a stash file.  The **-f**
argument can be used to override the *keyfile* specified in
:ref:`kdc.conf(5)`.

.. _kdb5_util_stash_end:

dump
~~~~

.. _kdb5_util_dump:

    **dump** [**-old**\|\ **-b6**\|\ **-b7**\|\ **-ov**\|\ **-r13**]
    [**-verbose**] [**-mkey_convert**] [**-new_mkey_file** *mkey_file*]
    [**-rev**] [**-recurse**] [*filename* [*principals*...]]

Dumps the current Kerberos and KADM5 database into an ASCII file.  By
default, the database is dumped in current format, "kdb5_util
load_dump version 6".  If filename is not specified, or is the string
"-", the dump is sent to standard output.  Options:

**-old**
    causes the dump to be in the Kerberos 5 Beta 5 and earlier dump
    format ("kdb5_edit load_dump version 2.0").

**-b6**
    causes the dump to be in the Kerberos 5 Beta 6 format ("kdb5_edit
    load_dump version 3.0").

**-b7**
    causes the dump to be in the Kerberos 5 Beta 7 format ("kdb5_util
    load_dump version 4").  This was the dump format produced on
    releases prior to 1.2.2.

**-ov**
    causes the dump to be in "ovsec_adm_export" format.

**-r13**
    causes the dump to be in the Kerberos 5 1.3 format ("kdb5_util
    load_dump version 5").  This was the dump format produced on
    releases prior to 1.8.

**-r18**
    causes the dump to be in the Kerberos 5 1.8 format ("kdb5_util
    load_dump version 6").  This was the dump format produced on
    releases prior to 1.11.

**-verbose**
    causes the name of each principal and policy to be printed as it
    is dumped.

**-mkey_convert**
    prompts for a new master key.  This new master key will be used to
    re-encrypt principal key data in the dumpfile.  The principal keys
    themselves will not be changed.

**-new_mkey_file** *mkey_file*
    the filename of a stash file.  The master key in this stash file
    will be used to re-encrypt the key data in the dumpfile.  The key
    data in the database will not be changed.

**-rev**
    dumps in reverse order.  This may recover principals that do not
    dump normally, in cases where database corruption has occurred.

**-recurse**
    causes the dump to walk the database recursively (btree only).
    This may recover principals that do not dump normally, in cases
    where database corruption has occurred.  In cases of such
    corruption, this option will probably retrieve more principals
    than the **-rev** option will.

.. _kdb5_util_dump_end:

load
~~~~

.. _kdb5_util_load:

    **load** [**-old**\|\ **-b6**\|\ **-b7**\|\ **-ov**\|\ **-r13**]
    [**-hash**] [**-verbose**] [**-update**] *filename* [*dbname*]

Loads a database dump from the named file into the named database.  If
no option is given to determine the format of the dump file, the
format is detected automatically and handled as appropriate.  Unless
the **-update** option is given, **load** creates a new database
containing only the data in the dump file, overwriting the contents of
any previously existing database.  Note that when using the LDAP KDC
database module, the **-update** flag is required.

Options:

**-old**
    requires the database to be in the Kerberos 5 Beta 5 and earlier
    format ("kdb5_edit load_dump version 2.0").

**-b6**
    requires the database to be in the Kerberos 5 Beta 6 format
    ("kdb5_edit load_dump version 3.0").

**-b7**
    requires the database to be in the Kerberos 5 Beta 7 format
    ("kdb5_util load_dump version 4").

**-ov**
    requires the database to be in "ovsec_adm_import" format.  Must be
    used with the **-update** option.

**-r13**
    requires the database to be in Kerberos 5 1.3 format ("kdb5_util
    load_dump version 5").  This was the dump format produced on
    releases prior to 1.8.

**-r18**
    requires the database to be in Kerberos 5 1.8 format ("kdb5_util
    load_dump version 6").  This was the dump format produced on
    releases prior to 1.11.

**-hash**
    requires the database to be stored as a hash.  If this option is
    not specified, the database will be stored as a btree.  This
    option is not recommended, as databases stored in hash format are
    known to corrupt data and lose principals.

**-verbose**
    causes the name of each principal and policy to be printed as it
    is dumped.

**-update**
    records from the dump file are added to or updated in the existing
    database.  (This is useful in conjunction with an ovsec_adm_export
    format dump if you want to preserve per-principal policy
    information, since the current default format does not contain
    this data.)  Otherwise, a new database is created containing only
    what is in the dump file and the old one destroyed upon successful
    completion.

If specified, *dbname* overrides the value specified on the command
line or the default.

.. _kdb5_util_load_end:

ark
~~~

    **ark** [**-e** *enc*:*salt*,...] *principal*

Adds new random keys to *principal* at the next available key version
number.  Keys for the current highest key version number will be
preserved.  The **-e** option specifies the list of encryption and
salt types to be used for the new keys.

add_mkey
~~~~~~~~

    **add_mkey** [**-e** *etype*] [**-s**]

Adds a new master key to the master key principal, but does not mark
it as active.  Existing master keys will remain.  The **-e** option
specifies the encryption type of the new master key; see
:ref:`Encryption_and_salt_types` in :ref:`kdc.conf(5)` for a list of
possible values.  The **-s** option stashes the new master key in the
stash file, which will be created if it doesn't already exist.

After a new master key is added, it should be propagated to slave
servers via a manual or periodic invocation of :ref:`kprop(8)`.  Then,
the stash files on the slave servers should be updated with the
kdb5_util **stash** command.  Once those steps are complete, the key
is ready to be marked active with the kdb5_util **use_mkey** command.

use_mkey
~~~~~~~~

    **use_mkey** *mkeyVNO* [*time*]

Sets the activation time of the master key specified by *mkeyVNO*.
Once a master key becomes active, it will be used to encrypt newly
created principal keys.  If no *time* argument is given, the current
time is used, causing the specified master key version to become
active immediately.  The format for *time* is :ref:`getdate` string.

After a new master key becomes active, the kdb5_util
**update_princ_encryption** command can be used to update all
principal keys to be encrypted in the new master key.

list_mkeys
~~~~~~~~~~

    **list_mkeys**

List all master keys, from most recent to earliest, in the master key
principal.  The output will show the kvno, enctype, and salt type for
each mkey, similar to the output of :ref:`kadmin(1)` **getprinc**.  A
``*`` following an mkey denotes the currently active master key.

purge_mkeys
~~~~~~~~~~~

    **purge_mkeys** [**-f**] [**-n**] [**-v**]

Delete master keys from the master key principal that are not used to
protect any principals.  This command can be used to remove old master
keys all principal keys are protected by a newer master key.

**-f**
    does not prompt for confirmation.

**-n**
    performs a dry run, showing master keys that would be purged, but
    not actually purging any keys.

**-v**
    gives more verbose output.

update_princ_encryption
~~~~~~~~~~~~~~~~~~~~~~~

    **update_princ_encryption** [**-f**] [**-n**] [**-v**]
    [*princ-pattern*]

Update all principal records (or only those matching the
*princ-pattern* glob pattern) to re-encrypt the key data using the
active database master key, if they are encrypted using older
versions, and give a count at the end of the number of principals
updated.  If the **-f** option is not given, ask for confirmation
before starting to make changes.  The **-v** option causes each
principal processed to be listed, with an indication as to whether it
needed updating or not.  The **-n** option performs a dry run, only
showing the actions which would have been taken.


SEE ALSO
--------

:ref:`kadmin(1)`
