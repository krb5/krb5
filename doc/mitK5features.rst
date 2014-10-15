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
    - Latest stable: http://web.mit.edu/kerberos/krb5-1.13/
    - Supported: http://web.mit.edu/kerberos/krb5-1.12/
    - Supported: http://web.mit.edu/kerberos/krb5-1.11/
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

* Support for KCM credential cache starting from release 1.13

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

Release 1.12
 -   Plugin to control krb5_aname_to_localname and krb5_kuserok behavior   :ref:`localauth_plugin`
 -   Plugin to control hostname-to-realm mappings and the default realm    :ref:`hostrealm_plugin`
 -   GSSAPI extensions for constructing MIC tokens using IOV lists         :ref:`gssapi_mic_token`
 -   Principal may refer to nonexistent policies `Policy Refcount project <http://k5wiki.kerberos.org/wiki/Projects/Policy_refcount_elimination>`_
 -   Support for having no long-term keys for a principal `Principals Without Keys project <http://k5wiki.kerberos.org/wiki/Projects/Principals_without_keys>`_
 -   Collection support to the KEYRING credential cache type on Linux :ref:`ccache_definition`
 -   FAST OTP preauthentication module for the KDC which uses RADIUS to validate OTP token values :ref:`otp_preauth`
 -   Experimental Audit plugin for KDC processing `Audit project <http://k5wiki.kerberos.org/wiki/Projects/Audit>`_

Release 1.13

 -   Add support for accessing KDCs via an HTTPS proxy server using
     the `MS-KKDCP
     <http://msdn.microsoft.com/en-us/library/hh553774.aspx>`_
     protocol.
 -   Add support for `hierarchical incremental propagation
     <http://k5wiki.kerberos.org/wiki/Projects/Hierarchical_iprop>`_,
     where slaves can act as intermediates between an upstream master
     and other downstream slaves.
 -   Add support for configuring GSS mechanisms using
     ``/etc/gss/mech.d/*.conf`` files in addition to
     ``/etc/gss/mech``.
 -   Add support to the LDAP KDB module for `binding to the LDAP
     server using SASL
     <http://k5wiki.kerberos.org/wiki/Projects/LDAP_SASL_support>`_.
 -   The KDC listens for TCP connections by default.
 -   Fix a minor key disclosure vulnerability where using the
     "keepold" option to the kadmin randkey operation could return the
     old keys. `[CVE-2014-5351]
     <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5351>`_
 -   Add client support for the Kerberos Cache Manager protocol. If
     the host is running a Heimdal kcm daemon, caches served by the
     daemon can be accessed with the KCM: cache type.
 -   When built on OS X 10.7 and higher, use "KCM:" as the default
     cachetype, unless overridden by command-line options or
     krb5-config values.
 -   Add support for doing unlocked database dumps for the DB2 KDC
     back end, which would allow the KDC and kadmind to continue
     accessing the database during lengthy database dumps.

`Pre-authentication mechanisms`

- PW-SALT                                         :rfc:`4120#section-5.2.7.3`
- ENC-TIMESTAMP                                   :rfc:`4120#section-5.2.7.2`
- SAM-2
- FAST negotiation framework   (release 1.8)      :rfc:`6113`
- PKINIT with FAST on client   (release 1.10)     :rfc:`6113`
- PKINIT                                          :rfc:`4556`
- FX-COOKIE                                       :rfc:`6113#section-5.2`
- S4U-X509-USER                (release 1.8)      http://msdn.microsoft.com/en-us/library/cc246091
- OTP                          (release 1.12)     :ref:`otp_preauth`

`PRNG`

- modularity       (release 1.9)
- Yarrow PRNG      (release < 1.10)
- Fortuna PRNG     (release 1.9)       http://www.schneier.com/book-practical.html
- OS PRNG          (release 1.10)      OS's native PRNG
