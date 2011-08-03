Configuring Kerberos with OpenLDAP back-end
=================================================

.. note:: This document was copied from **Kerberos V5 System Administrator's Guide** with minor changes. Currently it is under review. Please, send your feedback, corrections and additions to krb5-bugs@mit.edu. Your contribution is greatly appreciated.

.. seealso:: :ref:`ldap_be_ubuntu`

1. Set up SSL on the OpenLDAP server and client to ensure secure communication when the KDC service and LDAP server are on different machines. *ldapi\://* can be used if the LDAP server and KDC service are running on the same machine.
         \A. Setting up SSL on the OpenLDAP server:
               a) Get a CA certificate using OpenSSL tools
               b) Configure OpenLDAP server for using SSL/TLS

                  For the latter, you need to specify the location of CA certificate location in *slapd.conf* file.

                  Refer to the following link for more information: http://www.openldap.org/doc/admin23/tls.html 

         \B. Setting up SSL on OpenLDAP Client:
               a) For the KDC and Admin Server, you need to do the client-side configuration in *ldap.conf*.

                  For example::

                                      TLS_CACERT /etc/openldap/certs/cacert.pem
                                      

2. Include the Kerberos schema file (*kerberos.schema*) in the configuration file (*slapd.conf*) on the LDAP Server, by providing the location where it is stored.

                include /etc/openldap/schema/kerberos.schema
                

3. Choose DNs for the KDC and kadmin servers to bind to the LDAP server, and create them if necessary. These DNs will be specified with the *ldap_kdc_dn* and *ldap_kadmind_dn* directives in *krb5.conf*; their passwords can be stashed with *kdb5_ldap_util stashsrvpw* and the resulting file specified with the *ldap_service_password_file* directive.

4. Choose a DN for the global Kerberos container entry (but do not create the entry at this time). This DN will be specified with the *ldap_kerberos_container_dn* directive in *krb5.conf*. Realm container entries will be created underneath this DN. Principal entries may exist either underneath the realm container (the default) or in separate trees referenced from the realm container.

5. Configure the LDAP server ACLs to enable the KDC and kadmin server DNs to read and write the Kerberos data.

      Sample access control information::

                access to dn.base=""
                        by * read
                
                access to dn.base="cn=Subschema"
                        by * read
                
                access to attrs=userPassword,userPKCS12
                        by self write
                        by * auth
                
                access to attrs=shadowLastChange
                        by self write
                        by * read
                
                # Providing access to realm container
                access to dn.subtree= "cn=EXAMPLE.COM,cn=krbcontainer,dc=example,dc=com"
                        by dn.exact="cn=kdc-service,dc=example,dc=com" read
                        by dn.exact="cn=adm-service,dc=example,dc=com" write
                        by * none
                
                # Providing access to principals, if not underneath realm container
                access to dn.subtree= "ou=users,dc=example,dc=com"
                        by dn.exact="cn=kdc-service,dc=example,dc=com" read
                        by dn.exact="cn=adm-service,dc=example,dc=com" write
                        by * none
                
                access to *
                        by * read
                

      If the locations of the container and principals or the DNs of the service objects for a realm are changed then this information should be updated.

6. Start the LDAP server as follows::

                slapd -h "ldapi:/// ldaps:///"
                

7. Modify the *krb5.conf* file to include LDAP specific items listed below::

                realms
                  database_module
                
                dbmodules
                  db_library
                  db_module_dir
                  ldap_kdc_dn
                  ldap_kadmind_dn
                  ldap_service_password_file
                  ldap_servers
                  ldap_conns_per_server
                


  For the sample krb5.conf file, refer to  :ref:`krb5_conf_sample_label`.  For more details, refer to :ref:`krb5.conf`

8. Create the realm using *kdb5_ldap_util* (see :ref:`ldap_create_realm_label`)::

                kdb5_ldap_util -D cn=admin,dc=example,dc=com create -subtrees ou=users,dc=example,dc=com -r EXAMPLE.COM -s
                


  Use the *-subtrees* option if the principals are to exist in a separate subtree from the realm container. Before executing the command, make sure that the subtree mentioned above *(ou=users,dc=example,dc=com)* exists. If the principals will exist underneath the realm container, omit the *-subtrees* option and do not worry about creating the principal subtree.

  For more information, refer to the section :ref:`ops_on_ldap_label`

  The realm object is created under the *ldap_kerberos_container_dn* specified in the configuration file. This operation will also create the Kerberos container, if not present already. This will be used to store information related to all realms.

9. Stash the password of the service object used by the KDC and Administration service to bind to the LDAP server using the *stashsrvpw* command of *kdb5_ldap_util* (see :ref:`stash_ldap_label`). The object DN should be the same as *ldap_kdc_dn* and *ldap_kadmind_dn* values specified in the *krb5.conf* file::

                kdb5_ldap_util -D cn=admin,dc=example,dc=com stashsrvpw -f /etc/kerberos/service.keyfile cn=krbadmin,dc=example,dc=com
                

10. Add *krb5principalname* to the indexes in *slapd.conf* to speed up the access. 

With the LDAP back end it is possible to provide aliases for principal entries. Currently we provide no mechanism provided for creating aliases, so it must be done by direct manipulation of the LDAP entries.

An entry with aliases contains multiple values of the *krbPrincipalName* attribute. Since LDAP attribute values are not ordered, it is necessary to specify which principal name is canonical, by using the *krbCanonicalName* attribute. Therefore, to create aliases for an entry, first set the *krbCanonicalName* attribute of the entry to the canonical principal name (which should be identical to the pre-existing *krbPrincipalName* value), and then add additional *krbPrincipalName* attributes for the aliases.

Principal aliases are only returned by the KDC when the client requests canonicalization. Canonicalization is normally requested for service principals; for client principals, an explicit flag is often required (e.g. *kinit -C*) and canonicalization is only performed for initial ticket requests. 

----------------------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___conf_ldap
