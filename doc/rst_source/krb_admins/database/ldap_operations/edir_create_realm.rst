.. _edir_create_realm_label:


eDir: Creating a Kerberos realm
=================================

See :ref:`ldap_create_realm_label`

The following are the eDirectory specific options

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_create_edir:
   :end-before: _kdb5_ldap_util_create_edir_end:
     

EXAMPLE::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu create -sscope 2
     -subtree ou=users,dc=example,dc=com -kdcdn cn=krbkdc,dc=example,dc=com -admindn cn=krbadmin,dc=example,dc=com -r ATHENA.MIT.EDU

     Password for "cn=admin,dc=example,dc=com":
     Initializing database for realm 'ATHENA.MIT.EDU'
     You will be prompted for the database Master Password.
     It is important that you NOT FORGET this password.
     Enter KDC database master key:
     Re-enter KDC database master key to verify:
     shell%
     

.. _edir_mod_realm_label:


eDir: Modifying a Kerberos realm
=================================

See :ref:`ldap_mod_realm_label`

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_modify_edir:
   :end-before: _kdb5_ldap_util_modify_edir_end:
     

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


