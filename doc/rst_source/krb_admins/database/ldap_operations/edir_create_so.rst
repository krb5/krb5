eDir: Creating a Service Object
========================================

To create a service object in directory and assign appropriate rights on the container holding kerberos data, use the following command::

     create_service -kdc|-admin|-pwd [-servicehost service_host_list] [-realm realm_list] [-randpw|
     -fileonly] [-filename] service_dn
     
Options are as follows

================================================== ============================================
-kdc                                                   Specifies the KDC service 
-admin                                                 Specifies the Administration service 
-pwd                                                   Specifies the Password service 
-servicehost *service_host_list*                       Specifies the list of entries separated by a colon (:). Each entry consists of the hostname or IP address of the server hosting the service, transport protocol and the port number of the service separated by a pound sign (#). For example  *server1#tcp#88:server2#udp#89*.
-realm *realm_list*                                       Specifies the list of realms that are to be associated with this service. The list contains the name of the realms separated by a colon (:). 
-randpw                                                  Generates and sets a random password. This option is used to set the random password for the service object in directory and also to store it in the file. *-fileonly* option cannot be used with *-randpw* option. 
-fileonly                                                Stores the password only in a file and not in directory. The *-randpw* option can not be used when *-fileonly* option is specified. 
-f *filename*                                            Specifies the complete path of the file where the service object password is stashed. If this option is not specified, the default file will be */usr/local/var/service_passwd* 
service_dn                                               Specifies the Distinguished Name (DN) of the Kerberos service to be created.
================================================== ============================================

For example::

              shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu
              create_service -kdc -randpw -f /home/andrew/service_passwd cn=service-kdc,dc=example,dc=com


              Password for "cn=admin,dc=example,dc=com":
              File does not exist. Creating the file /home/andrew/service_passwd...
              shell%
              


------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


