Add administrators to the Kerberos database
===============================================

Next you need to add administrative principals to the Kerberos database. (You must add at least one now.) To do this, use *kadmin.local* on the master KDC. The administrative principals you create should be the ones you added to the ACL file. (See :ref:`admin_acl_label`.) In the following example, the administration principal *admin/admin* is created::

     shell% /usr/local/sbin/kadmin.local
     kadmin.local: addprinc admin/admin@ATHENA.MIT.EDU
     NOTICE: no policy specified for "admin/admin@ATHENA.MIT.EDU";
     assigning "default".
     Enter password for principal admin/admin@ATHENA.MIT.EDU:  <= Enter a password.
     Re-enter password for principal admin/admin@ATHENA.MIT.EDU:  <= Type it again.
     Principal "admin/admin@ATHENA.MIT.EDU" created.
     kadmin.local:
     
------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc


