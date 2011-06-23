Destroying a Kerberos realm
===============================================


To destroy a Kerberos realm, use the command as follows::


   destroy [-f] [-r realm]

Options are as follows

============= =======================
-f             If specified, will not prompt the user for confirmation. 
-r *realm*     Specifies the Kerberos realm of the database; by default the realm returned by krb5_default_local_realm (3)is used. 
============= =======================

|

For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldap-server1.mit.edu destroy -r ATHENA.MIT.EDU


     Password for "cn=admin,dc=example,dc=com":
     Deleting KDC database of 'ATHENA.MIT.EDU', are you sure?
     type 'yes' to confirm)? Yes
     OK, deleting database of 'ATHENA.MIT.EDU'...
     shell%

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_ldap


