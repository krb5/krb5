*kadmin* options
=================


You can invoke **kadmin** or **kadmin.local** with any of the following options:

======================= ============================================
-r *REALM*               Use REALM as the default Kerberos realm for the database. 
-p *principal*           Use the Kerberos principal principal to authenticate to Kerberos. If this option is not given, *kadmin* will append admin to either the primary principal name, the environment variable USER, or to the username obtained from getpwuid, in order of preference. 
-q *query*               Pass query directly to *kadmin*. This is useful for writing scripts that pass specific queries to *kadmin*.
======================= ============================================

You can invoke **kadmin** with any of the following options: 

================================== ================================================
-k [-t keytab]                     Use the *keytab* to decrypt the KDC response instead of prompting for a password on the TTY. In this case, the principal will be *host/hostname*. If *-t* is not used to specify a keytab, then the default keytab will be used. 
-c *credentials_cache*             Use *credentials_cache* as the credentials cache. The credentials cache should contain a service ticket for the *kadmin/admin* service, which can be acquired with the *kinit* program. If this option is not specified, *kadmin* requests a new service ticket from the KDC, and stores it in its own temporary ccache. 
-w *password*                      Use password as the password instead of prompting for one on the TTY. Note: placing the password for a Kerberos principal with administration access into a shell script can be dangerous if unauthorized users gain read access to the script. 
-x *db_args*                       Specifies the database specific arguments. 
-x host=*<hostname>*               Specifies the LDAP server to connect to by a LDAP URI. It is recommend to use ldapi:// or ldaps:// interface to connect to the LDAP server. 
-x binddn=*<bind_dn>*              Specifies the Distinguished Name (DN) of the object used by the administration server to bind to the LDAP server. This object should have the read and write rights on the realm container, principal container and realm subtree. 
-x bindpwd=*<bind_password>*       Specifies the password for the above mentioned binddn. It is recommended not to use this option. Instead, the password can be stashed using the *stashsrvpw* command of *kdb5_ldap_util*.  Note: This database specific argument is applicable only to *kadmin.local* and the KADM5 server.
-s admin_server[:port]               Specifies the admin server that *kadmin* should contact.
================================== ================================================


You can invoke **kadmin.local** with an of the follwing options: 

======================= ===============================================
-d\_ *dbname*             Specifies the name of the Kerberos database. 
-e *"enctypes ..."*      Sets the list of cryptosystem and salt types to be used for any new keys created. See Supported Encryption Types and Salts for available types. 
-m                       Do not authenticate using a keytab. This option will cause *kadmin* to prompt for the master database password.
======================= ===============================================

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db

