Creating and destroying a Kerberos database
===================================================

If you need to create a new Kerberos database, use the :ref:`kdb5_util(8)` **create** command.

.. include:: ../../admin_commands/kdb5_util.rst
   :start-after: _kdb5_util_create: 
   :end-before: _kdb5_util_create_end:


If you need to destroy the current Kerberos database, use the :ref:`kdb5_util(8)` **destroy** command.

.. include:: ../../admin_commands/kdb5_util.rst
   :start-after: _kdb5_util_destroy: 
   :end-before: _kdb5_util_destroy_end:

EXAMPLES::

     shell% /usr/local/sbin/kdb5_util -r ATHENA.MIT.EDU create -s
     kdb5_util: No such file or directory while setting active database to'/usr/local/var/krb5kdc/principal'
     Initializing database '/usr/local/var/krb5kdc/principal' for realm 'ATHENA.MIT.EDU',
     master key name 'K/M@ATHENA.MIT.EDU'
     You will be prompted for the database Master Password.
     It is important that you NOT FORGET this password.
     Enter KDC database master key:  <= Type the master password.
     Re-enter KDC database master key to verify:  <= Type it again.
     shell%
     

     shell% /usr/local/sbin/kdb5_util -r ATHENA.MIT.EDU destroy
     kdb5_util: Deleting KDC database stored in /usr/local/var/krb5kdc/principal, are you sure (type yes to confirm)? <== yes
     OK, deleting database '/usr/local/var/krb5kdc/principal'...
     shell%
     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_operations

