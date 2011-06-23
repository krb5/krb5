Listing available Kerberos realms
===============================================

To display the list of the realms, use the **list** command.

|

For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu list
     Password for "cn=admin,dc=example,dc=com":
     ATHENA.MIT.EDU
     OPENLDAP.MIT.EDU
     MEDIA-LAB.MIT.EDU
     shell%
     

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_ldap


