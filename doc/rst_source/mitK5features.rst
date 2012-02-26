.. highlight:: rst

.. _mitK5features:

MIT Kerberos Features
=====================

http://web.mit.edu/kerberos


Quick facts
-----------

   ====================================================== ======================================= =============================================================================
    Latest stable  version                                 1.9.2
    Supported versions                                     1.7.3, 1.8.5, 1.9.2
    Release cycle                                          9 - 12 months
    Supported platforms/OS distributions                   Solaris
                                                               - SPARC
                                                               - x86_64/x86
                                                           GNU/Linux
                                                               - Debian       x86_64/x86
                                                               - Ubuntu       x86_64/x86
                                                               - RedHat       x86_64/x86
                                                           BSD
                                                               - NetBSD x86_64/x86
    Crypto backends                                        - OpenSSL 1.0\+                          - http://www.openssl.org
                                                           - builtin                                - MIT Kerberos native crypto library
                                                           - NSS 3.12.9\+                           - Mozilla's Network Security Services.
                                                                                                      http://www.mozilla.org/projects/security/pki/nss
    Database backends                                      - LDAP
                                                           - DB2
    krb4 support                                           < 1.8
    DES support                                            configurable                             http://k5wiki.kerberos.org/wiki/Projects/Disable_DES
    GSS-API S4U extensions                                 1.8+                                     http://msdn.microsoft.com/en-us/library/cc246071
                                                               - S4U2Proxy
                                                               - S4U2Proxy
    GSS-API naming extensions                              1.8+                                     http://tools.ietf.org/html/draft-ietf-kitten-gssapi-naming-exts-11

    GSS-API extensions for storing delegated credentials   1.8+                                     :rfc:`5588`

    License                                                :ref:`mitK5license`
   ====================================================== ======================================= =============================================================================


Interoperabiity
---------------

Microsoft
~~~~~~~~~

Starting from version 1.7:

* Follow client principal referrals in the client library when
  obtaining initial tickets.

* KDC can issue realm referrals for service principals based on domain names.

* Extensions supporting DCE RPC, including three-leg GSS context setup
  and unencapsulated GSS tokens inside SPNEGO.

* Microsoft GSS_WrapEX, implemented using the gss_iov API, which is
  similar to the equivalent SSPI functionality.  This is needed to
  support some instances of DCE RPC.

* NTLM recognition support in GSS-API, to facilitate dropping in an
  NTLM implementation for improved compatibility with older releases
  of Microsoft Windows.

* KDC support for principal aliases, if the back end supports them.
  Currently, only the LDAP back end supports aliases.

* Support Microsoft set/change password (RFC 3244) protocol in
  kadmind.

* Implement client and KDC support for GSS_C_DELEG_POLICY_FLAG, which
  allows a GSS application to request credential delegation only if
  permitted by KDC policy.


Starting from version 1.8:

* Microsoft Services for User (S4U) compatibility`


Heimdal
~~~~~~~

* Support for reading Heimdal database starting from version 1.8


Feature list
~~~~~~~~~~~~

   =============================================== =========== ============================================
    \                                              Available    Additional information
   =============================================== =========== ============================================
    Credentials delegation                         1.7          :rfc:`5896`
    Cross-realm authentication and referrals       1.7          http://tools.ietf.org/html/draft-ietf-krb-wg-kerberos-referrals-12
    Master key migration                           1.7          http://k5wiki.kerberos.org/wiki/Projects/Master_Key_Migration
    PKINIT                                         1.7          :rfc:`4556`
    Anonymous PKINIT                               1.8          :rfc:`6112` http://k5wiki.kerberos.org/wiki/Projects/Anonymous_pkinit
    Constrained delegation                         1.8          http://k5wiki.kerberos.org/wiki/Projects/ConstrainedDelegation
    IAKERB                                         1.8          http://tools.ietf.org/html/draft-ietf-krb-wg-iakerb-02
    Heimdal bridge plugin for KDC backend          1.8
    Advance warning on password expiry             1.9
    Camellia encryption (CTS-CMAC mode)            1.9          experimental http://tools.ietf.org/html/draft-ietf-krb-wg-camellia-cts-00
    KDC support for SecurID preauthentication      1.9          http://k5wiki.kerberos.org/wiki/Projects/SecurID_SAM_support
    kadmin over IPv6                               1.9
    Trace logging                                  1.9          http://k5wiki.kerberos.org/wiki/Projects/Trace_logging
    GSSAPI/KRB5 multi-realm support
    Plugins to test password quality               1.9          http://k5wiki.kerberos.org/wiki/Projects/Password_quality_pluggable_interface
    Plugins to synchronize password changes        1.9
    Parallel KDC                                   1.9
    GS2                                            1.9          :rfc:`5801` :rfc:`5587` http://k5wiki.kerberos.org/wiki/Projects/GS2
    Purging old keys                               1.9
    Naming extensions for delegation chain         1.9
    Password expiration API                        1.9
    Windows client support   (build-only)          1.9
    pre-auth mechanisms:
     - PW-SALT                                                  :rfc:`4120#section-5.2.7.3`
     - ENC-TIMESTAMP                                            :rfc:`4120#section-5.2.7.2`
     - SAM-2
     - FAST negotiation framework                  1.8          :rfc:`6113`
     - PKINIT                                                   :rfc:`4556`
     - FX-COOKIE                                                :rfc:`6113#section-5.2`
     - S4U-X509-USER                               1.8          http://msdn.microsoft.com/en-us/library/cc246091

    PRNG
      - modularity:                                   1.9
      - Yarrow PRNG                                   < 1.10
      - Fortuna PRNG                                  1.9       http://www.schneier.com/book-practical.html
      - OS PRNG                                       1.10      OS's native PRNG
    Zero configuration
    IPv6 support in iprop
   =============================================== =========== ============================================


Feedback
--------

Please, provide your feedback on this document at
krb5-bugs@mit.edu?subject=Documentation___krb5_implementation_features
