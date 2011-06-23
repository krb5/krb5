eDir: Retrieving Service Object Information
==============================================================

To display the attributes of a service, use the folowing command::

           view_service service_dn

where *service_dn* specifies the Distinguished Name (DN) of the Kerberos service to be viewed. 

For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu
     view_service cn=service-kdc,dc=example,dc=com


     Password for "cn=admin,dc=example,dc=com":
     Service dn: cn=service-kdc,dc=example,dc=com
     Service type: kdc
     Service host list:
     Realm DN list: cn=ATHENA.MIT.EDU,cn=Kerberos,dc=example,dc=com
     shell%
     


------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


