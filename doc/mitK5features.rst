.. highlight:: rst

.. toctree::
    :hidden:

    mitK5license.rst

.. _mitK5features:

MIT Kerberos features
=====================

http://web.mit.edu/kerberos


Quick facts
-----------

License - :ref:`mitK5license`

Releases:
    - Latest stable: http://web.mit.edu/kerberos/krb5-1.11/
    - Supported: http://web.mit.edu/kerberos/krb5-1.10/
    - Release cycle: 9 -- 12 months

Supported platforms \/ OS distributions:
    - Windows (KfW 4.0): Windows 7, Vista, XP
    - Solaris: SPARC, x86_64/x86
    - GNU/Linux: Debian x86_64/x86, Ubuntu x86_64/x86, RedHat x86_64/x86
    - BSD: NetBSD x86_64/x86

Crypto backends:
    - builtin - MIT Kerberos native crypto library
    - OpenSSL (1.0\+) - http://www.openssl.org
    - NSS (3.12.9\+) - http://www.mozilla.org/projects/security/pki/nss

Database backends: LDAP, DB2

krb4 support: Kerberos 5 release < 1.8

DES support: configurable (See :ref:`retiring-des`)

Interoperability
----------------

`Microsoft`

Starting from release 1.7:

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

* Support Microsoft set/change password (:rfc:`3244`) protocol in
  kadmind.

* Implement client and KDC support for GSS_C_DELEG_POLICY_FLAG, which
  allows a GSS application to request credential delegation only if
  permitted by KDC policy.


Starting from release 1.8:

* Microsoft Services for User (S4U) compatibility


`Heimdal`

* Support for reading Heimdal database starting from release 1.8


Feature list
------------

For more information on the specific project see http://k5wiki.kerberos.org/wiki/Projects

Release 1.7
 -   Credentials delegation                   :rfc:`5896`
 -   Cross-realm authentication and referrals :rfc:`6806`
 -   Master key migration
 -   PKINIT                                   :rfc:`4556` :ref:`pkinit`

Release 1.8
 -   Anonymous PKINIT         :rfc:`6112` :ref:`anonymous_pkinit`
 -   Constrained delegation
 -   IAKERB                   http://tools.ietf.org/html/draft-ietf-krb-wg-iakerb-02
 -   Heimdal bridge plugin for KDC backend
 -   GSS-API S4U extensions   http://msdn.microsoft.com/en-us/library/cc246071
 -   GSS-API naming extensions                            :rfc:`6680`
 -   GSS-API extensions for storing delegated credentials :rfc:`5588`

Release 1.9
 -   Advance warning on password expiry
 -   Camellia encryption (CTS-CMAC mode)       :rfc:`6803`
 -   KDC support for SecurID preauthentication
 -   kadmin over IPv6
 -   Trace logging                             :ref:`trace_logging`
 -   GSSAPI/KRB5 multi-realm support
 -   Plugin to test password quality           :ref:`pwqual_plugin`
 -   Plugin to synchronize password changes    :ref:`kadm5_hook_plugin`
 -   Parallel KDC
 -   GSS-API extentions for SASL GS2 bridge    :rfc:`5801` :rfc:`5587`
 -   Purging old keys
 -   Naming extensions for delegation chain
 -   Password expiration API
 -   Windows client support   (build-only)
 -   IPv6 support in iprop

Release 1.10
 -   Plugin interface for configuration        :ref:`profile_plugin`
 -   Credentials for multiple identities       :ref:`ccselect_plugin`

Release 1.11
 -   Client support for FAST OTP               :rfc:`6560`
 -   GSS-API extensions for credential locations
 -   Responder mechanism

`Pre-authentication mechanisms`

- PW-SALT                                         :rfc:`4120#section-5.2.7.3`
- ENC-TIMESTAMP                                   :rfc:`4120#section-5.2.7.2`
- SAM-2
- FAST negotiation framework   (release 1.8)      :rfc:`6113`
- PKINIT with FAST on client   (release 1.10)     :rfc:`6113`
- PKINIT                                          :rfc:`4556`
- FX-COOKIE                                       :rfc:`6113#section-5.2`
- S4U-X509-USER                (release 1.8)      http://msdn.microsoft.com/en-us/library/cc246091

`PRNG`

- modularity       (release 1.9)
- Yarrow PRNG      (release < 1.10)
- Fortuna PRNG     (release 1.9)       http://www.schneier.com/book-practical.html
- OS PRNG          (release 1.10)      OS's native PRNG
