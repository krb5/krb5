eDir: Modifying a Service Object 
=================================

To modify the attributes of a service and assign appropriate rights, if realm associations are changed, use the following command::

     modify_service [-servicehost service_host_list |[-clearservicehost service_host_list] [-addservicehost service_host_list]] [-realm realm_list | [-clearrealm realm_list] [-addrealm realm_list]] service_dn
     


Options are as follows


========================================= ==================================================
-servicehost *service_host_list*            List of entries separated by a colon (:) where each entry consists of host name or IP address of the server hosting the service, transport protocol, and port number of the service separated by a pound sign (#). This list replaces the existing list. For example, *server1#tcp#88:server2#udp#89*
-clearservicehost *service_host_list*           Specifies the list of servicehost entries to be removed from the existing list. This is a colon separated list. 
-addservicehost *service_host_list*           Specifies the list of servicehost entries to be added to the existing list. This is a colon separated list. 
-realm *realm_list*                                Specifies the list of realms that are to be associated with this service. The list contains the name of the realms separated by a colon (:). This list replaces the existing list. 
-clearrealm *realm_list*                     Specifies the list of realms to be removed from the existing list. The list contains the name of the realms separated by a colon (:). 
-addrealm *realm_list*                       Specifies the list of realms to be added to the existing list. The list contains the name of the realms separated by a colon (:). 
service_dn                                  Specifies the Distinguished Name (DN) of the Kerberos service to be modified. 
========================================= ==================================================

For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu
     modify_service -realm ATHENA.MIT.EDU cn=service-kdc,dc=example,dc=com


     Password for "cn=admin,dc=example,dc=com":
     Changing rights for the service object. Please wait ... done
     shell%
     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


