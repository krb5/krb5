.. highlight:: rst

.. note:: This is a Draft. The list is incomplete.

MIT Kerberos features
=======================================

http://web.mit.edu/kerberos

Quick facts
-----------------------

   +---------------------------------+------------------------+
   |                                 |       MIT              |
   +=================================+========================+
   | Latest stable  version          | 1.9.1                  |
   +---------------------------------+------------------------+
   | Supported versions              | 1.7.2, 1.8.4, 1.9.1    |
   +---------------------------------+------------------------+
   | Release cycle                   | 9 - 12 months          |
   +---------------------------------+------------------------+
   | Supported platforms/            | - Solaris              | 
   | OS distributions                |    - SPARC             |
   |                                 |    - x86_64/x86        |
   |                                 | - GNU/Linux            | 
   |                                 |    - Debian x86_64/x86 | 
   |                                 |    - Ubuntu x86_64/x86 | 
   |                                 |    - RedHat x86_64/x86 | 
   |                                 | - BSD                  | 
   |                                 |    - NetBSD x86_64/x86 | 
   +---------------------------------+------------------------+
   | Crypto backends                 | - OSSL 1.0+            |
   |                                 | - builtin              |
   |                                 | - NSS 3.12.9+          |
   +---------------------------------+------------------------+
   | Database backends               | - LDAP                 |
   |                                 | - DB2                  | 
   +---------------------------------+------------------------+
   | krb4 support                    |  < 1.8                 |
   +---------------------------------+------------------------+
   | DES support                     |  configurable          |
   +---------------------------------+------------------------+
   | Extensions (1.8+)               | - S4U2Self             |
   |                                 | - S4U2Proxy            |
   |                                 | - GSS naming exts      |
   |                                 | - GSS to store creds   | 
   +---------------------------------+------------------------+
   | License                         |  .. toctree::          | 
   |                                 |                        | 
   |                                 |      mitK5license.rst  |
   +---------------------------------+------------------------+



Interoperabiity
---------------

Microsoft
~~~~~~~~~~

Starting from version 1.7:

* Follow client principal referrals in the client library when obtaining initial tickets.

* KDC can issue realm referrals for service principals based on domain names.

* Extensions supporting DCE RPC, including three-leg GSS context setup and unencapsulated GSS tokens inside SPNEGO.

* Microsoft GSS_WrapEX, implemented using the gss_iov API, which is similar to the equivalent SSPI functionality.  This is needed to support some instances of DCE RPC.

* NTLM recognition support in GSS-API, to facilitate dropping in an NTLM implementation for improved compatibility with older releases of Microsoft Windows.

* KDC support for principal aliases, if the back end supports them.  Currently, only the LDAP back end supports aliases.

* Support Microsoft set/change password (RFC 3244) protocol in kadmind.

* Implement client and KDC support for GSS_C_DELEG_POLICY_FLAG, which allows a GSS application to request credential delegation only if permitted by KDC policy.


Starting from version 1.8:

* Microsoft Services for User (S4U) compatibility`

Heimdal
~~~~~~~~~~

* Support for reading Heimdal database  starting from version 1.8


Feature list
--------------------------


   +-----------------------------------------------+-----------+-------------------+
   |                                               | Available | Additional        | 
   |                                               |           | information       | 
   +===============================================+===========+===================+
   | PKINIT                                        | 1.7       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Anonymous PKINIT                              | 1.8       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | IPv6 support in iprop                         |           |                   |
   +-----------------------------------------------+-----------+-------------------+
   | kadmin over IPv6                              |  1.9      |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Trace logging                                 |  1.9      |                   |
   +-----------------------------------------------+-----------+-------------------+
   | IAKERB                                        |  1.8      |                   |
   +-----------------------------------------------+-----------+-------------------+
   | GSSAPI/KRB5  multi-realm support              |           |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Plugins to test password quality              | 1.9       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Plugins to synchronize password changes       | 1.9       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Parallel KDC                                  |           |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Credentials delegation                        | 1.7       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Constrained delegation                        | 1.8       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Cross-realm auth and referrals                |  1.7      |                   |
   +-----------------------------------------------+-----------+-------------------+
   | GS2                                           | 1.9       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Purging old keys                              | 1.9       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Naming extensions for delegation chain        | 1.9       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Password expiration API                       | 1.9       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Windows client support   (build-only)         | 1.9       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | pre-auth mechanisms:                          | |         | |                 |
   |                                               | |         | |                 |
   |  - PW-SALT                                    | |         | | :rfc:`4120`     |
   |  - ENC-TIMESTAMP                              | |         | | :rfc:`4120`     |
   |  - SAM-2                                      | |         | |                 |
   |  - FAST negotiation framework                 | | 1.8     | |                 |
   |  - PKINIT                                     | |         | |                 |
   |  - FX-COOKIE                                  | |         | |                 |
   |  - S4U-X509-USER                              | |         | |                 |
   |                                               |           |                   |
   +-----------------------------------------------+-----------+-------------------+
   | KDC support for SecurID preauthentication     | 1.9       | SAM-2 protocol    |
   +-----------------------------------------------+-----------+-------------------+
   | Account lockout on bad login attempts         | 1.8       |                   | 
   +-----------------------------------------------+-----------+-------------------+
   | Camellia encryption (CTS-MAC mode)            | 1.9       | experimental      |
   |                                               |           |                   |
   +-----------------------------------------------+-----------+-------------------+
   | PRNG                                          | |         |                   |
   |                                               | |         |                   |
   | - modularity:                                 | | 1.9     |                   |
   | - Yarrow PRNG                                 | | < 1.10  |                   |
   | - Fortuna PRNG                                | | 1.9     |                   |
   | - OS PRNG                                     | | 1.10    |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Advance warning on password expiry            | 1.9       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Heimdal bridge plugin for KDC backend         | 1.8       |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Zero configuration                            |           |                   |
   +-----------------------------------------------+-----------+-------------------+
   | Master key migration                          | 1.7       |                   |
   +-----------------------------------------------+-----------+-------------------+
   |  						   |           |                   |
   +-----------------------------------------------+-----------+-------------------+



Report the problem
------------------


Please, provide your feedback on this document at krb5-bugs@mit.edu?subject=Documentation___krb5_implementation_features
 

