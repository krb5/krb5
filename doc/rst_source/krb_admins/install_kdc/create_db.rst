.. _create_db_label:

Create the database
=========================

You will use the :ref:`kdb5_util(8)` command on the master KDC to create the Kerberos database and the optional stash file.
The stash file is a local copy of the master key that resides in encrypted form on the KDC's local disk. The stash file is used to authenticate the KDC to itself automatically before starting the *kadmind* and *krb5kdc* daemons (e.g., as part of the machine's boot sequence). The stash file, like the keytab file (see :ref:`kt_file_label` for more information) is a potential point-of-entry for a break-in, and if compromised, would allow unrestricted access to the Kerberos database. If you choose to install a stash file, it should be readable only by root, and should exist only on the KDC's local disk. The file should not be part of any backup of the machine, unless access to the backup data is secured as tightly as access to the master password itself.

.. note:: If you choose not to install a stash file, the KDC will prompt you for the master key each time it starts up. This means that the KDC will not be able to start automatically, such as after a system reboot.

Note that kdb5_util will prompt you for the master key for the Kerberos database. This key can be any string. A good key is one you can remember, but that no one else can guess. Examples of bad keys are words that can be found in a dictionary, any common or popular name, especially a famous person (or cartoon character), your username in any form (e.g., forward, backward, repeated twice, etc.), and any of the sample keys that appear in this manual. One example of a key which might be good if it did not appear in this manual is "MITiys4K5!", which represents the sentence "MIT is your source for Kerberos 5!" (It's the first letter of each word, substituting the numeral "4" for the word "for", and includes the punctuation mark at the end.)

The following is an example of how to create a Kerberos database and stash file on the master KDC, using the :ref:`kdb5_util(8)` command. Replace *ATHENA.MIT.EDU* with the name of your Kerberos realm::

     shell% /usr/local/sbin/kdb5_util create -r ATHENA.MIT.EDU -s
     Initializing database '/usr/local/var/krb5kdc/principal' for realm 'ATHENA.MIT.EDU',
     master key name 'K/M@ATHENA.MIT.EDU'
     You will be prompted for the database Master Password.
     It is important that you NOT FORGET this password.
     Enter KDC database master key:  <= Type the master password.
     Re-enter KDC database master key to verify:  <= Type it again.
     shell%
     

This will create five files in the directory specified in your *kdc.conf* file (The default location is */usr/local/var/krb5kdc* directory): 

- two Kerberos database files, *principal*, and *principal.ok*; 
- the Kerberos administrative database file, *principal.kadm5*; 
- the administrative database lock file, *principal.kadm5.lock*;
- the stash file, in this example -  *.k5.ATHENA.MIT.EDU* ( by default it is *.k5.* prefix followed by the realm name of the database). If you do not want a stash file, run the above command without the *-s* option. 

For more information on administrating Kerberos database see :ref:`db_operations_label`.


------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc


