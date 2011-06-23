eDir: Destroying a Service Object
===================================


The *destroy_service* command is used to destroy an existing service::

   destroy_service [-force] [-f stashfilename] service_dn
     

Options are as follows 

=================== ======================
-force               If specified, will not prompt for user's confirmation, instead will force destruction of service. 
-f *stashfilename*    Complete path of the service password file from where the entry corresponding to the service_dn needs to be removed. 
service_dn             Distinguished Name (DN) of the Kerberos service to be destroyed. 
=================== ======================

For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu
     destroy_service cn=service-kdc,dc=example,dc=com

     Password for "cn=admin,dc=example,dc=com":
     This will delete the service object 'cn=service-kdc,dc=example,dc=com', are you sure?
     (type 'yes' to confirm)? Yes
     ** service object 'cn=service-kdc,dc=example,dc=com' deleted.
     shell%
     

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


