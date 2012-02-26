.. _addadmin_kdb:

Add administrators to the Kerberos database
===========================================

Next you need to add administrative principals (i.e. principals who
are allowed to administer Kerberos database) to the Kerberos database.
You *must* add at least one principal now to allow communication
between Kerberos administration daemon kadmind and kadmin program over
the network for the further Kerberos administration.  To do this, use
kadmin.local utility on the master KDC.  Note, that kadmin.local is
designed to be ran on the same host as the primary KDC without using
the Kerberos authentication to its database.  (However, one needs
administrative privileges on the local filesystem to access database
files for this command to succeed.)

The administrative principals you create should be the ones you added
to the ACL file. (See :ref:`admin_acl_label`.)

In the following example, the administrative principal ``admin/admin``
is created::

    shell% /usr/local/sbin/kadmin.local

    kadmin.local: addprinc admin/admin@ATHENA.MIT.EDU

    WARNING: no policy specified for "admin/admin@ATHENA.MIT.EDU";
    assigning "default".
    Enter password for principal admin/admin@ATHENA.MIT.EDU:  <= Enter a password.
    Re-enter password for principal admin/admin@ATHENA.MIT.EDU:  <= Type it again.
    Principal "admin/admin@ATHENA.MIT.EDU" created.
    kadmin.local:


Feedback
--------

Please, provide your feedback or suggest a new topic at
krb5-bugs@mit.edu?subject=Documentation___install_kdc
