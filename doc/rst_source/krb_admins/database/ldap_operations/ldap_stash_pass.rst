.. _stash_ldap_label:

Stashing service object's password
========================================


The :ref:`kdb5_ldap_util(8)` **stashsrvpw** command allows an administrator to store the password of service object in a file. 
The KDC and Administration server uses this password to authenticate to the LDAP server.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_list:
   :end-before: _kdb5_ldap_util_list_end:
     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_ldap


