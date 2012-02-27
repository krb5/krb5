.. _create_db:

Create the database
===================

You will use the :ref:`kdb5_util(8)` command on the master KDC to
create the Kerberos database and the optional :ref:`stash_definition`.

.. note:: If you choose not to install a stash file, the KDC will
          prompt you for the master key each time it starts up.  This
          means that the KDC will not be able to start automatically,
          such as after a system reboot.

:ref:`kdb5_util(8)` will prompt you for the master password for the
Kerberos database.  This password can be any string.  A good password
is one you can remember, but that no one else can guess.  Examples of
bad passwords are words that can be found in a dictionary, any common
or popular name, especially a famous person (or cartoon character),
your username in any form (e.g., forward, backward, repeated twice,
etc.), and any of the sample passwords that appear in this manual.
One example of a password which might be good if it did not appear in
this manual is "MITiys4K5!", which represents the sentence "MIT is
your source for Kerberos 5!"  (It's the first letter of each word,
substituting the numeral "4" for the word "for", and includes the
punctuation mark at the end.)

The following is an example of how to create a Kerberos database and
stash file on the master KDC, using the :ref:`kdb5_util(8)` command.
Replace ``ATHENA.MIT.EDU`` with the name of your Kerberos realm::

    shell% /usr/local/sbin/kdb5_util create -r ATHENA.MIT.EDU -s

    Initializing database '/usr/local/var/krb5kdc/principal' for realm 'ATHENA.MIT.EDU',
    master key name 'K/M@ATHENA.MIT.EDU'
    You will be prompted for the database Master Password.
    It is important that you NOT FORGET this password.
    Enter KDC database master key:  <= Type the master password.
    Re-enter KDC database master key to verify:  <= Type it again.
    shell%

This will create five files in the directory specified in your
:ref:`kdc.conf(5)` file (the default location is
``/usr/local/var/krb5kdc`` directory; see :ref:`mitK5defaults`):

* two Kerberos database files, ``principal``, and ``principal.ok``
* the Kerberos administrative database file, ``principal.kadm5``
* the administrative database lock file, ``principal.kadm5.lock``
* the stash file, in this example ``.k5.ATHENA.MIT.EDU`` (by default
  it is ``.k5.`` prefix followed by the realm name of the database).
  If you do not want a stash file, run the above command without the
  **-s** option.

For more information on administrating Kerberos database see
:ref:`db_operations`.


Feedback
--------

Please, provide your feedback or suggest a new topic at
krb5-bugs@mit.edu?subject=Documentation___install_kdc
