eDir: Passwords for Service Objects
============================================

The command *setsrvpw* allows an administrator to set password for service objects such as KDC and Administration server in eDirectory and store them in a file. The syntax is::

   setsrvpw [-randpw|-fileonly][-f filename] service_dn

Options are as follows:

================= =================================================================
-randpw            Generates and sets a random password on the directory object and stores it in the file. The -fileonly option can not be used if -randpw option is already specified. 
-fileonly          Stores the password only in a file and not in eDirectory. The -randpw option can not be used when -fileonly option is specified. 
-f *filename*      Specifies the complete path of the file where the service object password is stashed. If this option is not specified, the default file will be /usr/local/var/service_passwd. 
service_dn         Specifies the Distinguished Name (DN) of the service object whose password is to be set. 
================= =================================================================

For example::

     shell% kdb5_ldap_util setsrvpw -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu
     setsrvpw -f /home/andrew/conf_keyfile cn=service-kdc,dc=example,dc=com


     Password for "cn=admin,dc=example,dc=com":
     Password for "cn=service-kdc,dc=example,dc=com":
     Re-enter password for "cn=service-kdc,dc=example,dc=com":
     shell%
     

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


