.. _stash_ldap_label:

Stashing Service object's password
========================================

::

     stashsrvpw [-f filename] servicedn

This command allows an administrator to store the password of service object in a file. The KDC and Administration server uses this password to authenticate to the LDAP server.

Options are as follows

=============== ==================================
-f *filename*     Specifies the complete path of the service password file. By default, /usr/local/var/service_passwd is used. 
servicedn          Specifies the Distinguished Name (DN) of the service object whose password is to be stored in file. 
=============== ==================================

|

For example::

     shell% kdb5_ldap_util stashsrvpw -f /home/andrew/conf_keyle cn=service-kdc,dc=example,dc=com


     Password for "cn=service-kdc,dc=example,dc=com":
     Re-enter password for "cn=service-kdc,dc=example,dc=com":
     shell%
     

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_ldap


