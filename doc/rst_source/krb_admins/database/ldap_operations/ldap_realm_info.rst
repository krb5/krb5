Retrieving information about a Kerberos realm
===============================================

To display the attributes of a realm, use the command as follows::

     view [-r realm]

where *-r realm* specifies the Kerberos realm of the database; by default the realm returned by krb5_default_local_realm (3)is used. 

|

For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu view -r ATHENA.MIT.EDU


     Password for "cn=admin,dc=example,dc=com":
     Realm Name: ATHENA.MIT.EDU
     Subtree: ou=users,dc=example,dc=com
     Subtree: ou=servers,dc=example,dc=com
     SearchScope: ONE
     Maximum ticket life: 0 days 01:00:00
     Maximum renewable life: 0 days 10:00:00
     Ticket flags: DISALLOW_FORWARDABLE
     shell%
     

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_ldap


