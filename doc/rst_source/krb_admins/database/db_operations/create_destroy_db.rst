Creating and destroying a Kerberos database
===================================================

If you need to create a new Kerberos database, use the *kdb5_util create* command. The syntax is::

     kdb5_util create [-s]
     

If you specify the -s option, kdb5_util will stash a copy of the master key in a stash file. (See :ref:`create_stash`) For example::

     shell% /usr/local/sbin/kdb5_util -r ATHENA.MIT.EDU create -s
     kdb5_util: No such file or directory while setting active database to
     => '/usr/local/var/krb5kdc/principal'
     Initializing database '/usr/local/var/krb5kdc/principal' for
     => realm 'ATHENA.MIT.EDU',
     master key name 'K/M@ATHENA.MIT.EDU'
     You will be prompted for the database Master Password.
     It is important that you NOT FORGET this password.
     Enter KDC database master key:  <= Type the master password.
     Re-enter KDC database master key to verify:  <= Type it again.
     shell%
     

If you need to destroy the current Kerberos database, use the *kdb5_util destroy* command. The syntax is::

     kdb5_util destroy [-f]
     

The *destroy* command destroys the database, first overwriting the disk sectors and then unlinking the files. If you specify the *-f* option, *kdb5_util* will not prompt you for a confirmation before destroying the database.

::

     shell% /usr/local/sbin/kdb5_util -r ATHENA.MIT.EDU destroy
     kdb5_util: Deleting KDC database stored in /usr/local/var/krb5kdc/principal, are you sure
     (type yes to confirm)? <== yes
     OK, deleting database '/usr/local/var/krb5kdc/principal'...
     
     shell%
     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_operations

