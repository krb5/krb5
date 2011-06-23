.. _edir_create_realm_label:


eDir: Creating a Kerberos realm
=================================

See :ref:`ldap_create_realm_label`

The following are the eDirectory specific options

==================================== ==============================================
-kdcdn *kdc_servce_list*               Specifies the list of KDC service objects serving the realm. The list contains the DNs of the KDC service objects separated by colon(:). 
-admindn *admin_service_list*           Specifies the list of Administration service objects serving the realm. The list contains the DNs of the Administration service objects separated by colon(:). 
==================================== ==============================================

|

For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu create -sscope 2
     -subtree ou=users,dc=example,dc=com -kdcdn cn=krbkdc,dc=example,dc=com -admindn cn=krbadmin,dc=example,dc=com -r ATHENA.MIT.EDU



     Password for "cn=admin,dc=example,dc=com":
     Initializing database for realm 'ATHENA.MIT.EDU'
     You will be prompted for the database Master Password.
     It is important that you NOT FORGET this password.
     Enter KDC database master key:
     Re-enter KDC database master key to verify:
     shell%
     


------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


