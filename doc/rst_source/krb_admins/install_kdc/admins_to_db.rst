.. _addadmin_kdb:

Add administrators to the Kerberos database
===========================================

Next you need to add administrative principals (i.e. principals who
are allowed to administer Kerberos database) to the Kerberos database.
You *must* add at least one principal now to allow communication
between the Kerberos administration daemon kadmind and the kadmin
program over the network for further administration.  To do this, use
the kadmin.local utility on the master KDC.  kadmin.local is designed
to be run on the master KDC host without using Kerberos authentication
to its database; instead, it must have read and write access to the
Kerberos database on the local filesystem.

The administrative principals you create should be the ones you added
to the ACL file (see :ref:`admin_acl`).

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
