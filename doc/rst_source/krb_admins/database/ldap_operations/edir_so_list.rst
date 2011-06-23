eDir: Listing Available Service Objects 
===========================================

The *list_service* command lists the name of services under a given base in directory::

   list_service [-basedn base_dn]

where *-basedn base_dn* option  specifies the base DN for searching the policies, limiting the search to a particular subtree. If this option is not provided, LDAP Server specific search base will be used. For e.g., in the case of OpenLDAP, value of *defaultsearchbase* from *slapd.conf* file will be used, where as in the case of eDirectory, the default value for the base DN is *root*. 

For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu list_service


     Password for "cn=admin,dc=example,dc=com":
     cn=service-kdc,dc=example,dc=com
     cn=service-adm,dc=example,dc=com
     cn=service-pwd,dc=example,dc=com
     shell%
     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


