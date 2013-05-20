.. _kdc.conf(5):

kdc.conf
========

The kdc.conf file supplements :ref:`krb5.conf(5)` for programs which
are typically only used on a KDC, such as the :ref:`krb5kdc(8)` and
:ref:`kadmind(8)` daemons and the :ref:`kdb5_util(8)` program.
Relations documented here may also be specified in krb5.conf; for the
KDC programs mentioned, krb5.conf and kdc.conf will be merged into a
single configuration profile.

Normally, the kdc.conf file is found in the KDC state directory,
|kdcdir|.  You can override the default location by setting the
environment variable **KRB5_KDC_PROFILE**.

Please note that you need to restart the KDC daemon for any configuration
changes to take effect.

Structure
---------

The kdc.conf file is set up in the same format as the
:ref:`krb5.conf(5)` file.


Sections
--------

The kdc.conf file may contain the following sections:

==================== =================================================
:ref:`kdcdefaults`   Default values for KDC behavior
:ref:`kdc_realms`    Realm-specific database configuration and settings
:ref:`dbdefaults`    Default database settings
:ref:`dbmodules`     Per-database settings
:ref:`logging`       Controls how Kerberos daemons perform logging
==================== =================================================


.. _kdcdefaults:

[kdcdefaults]
~~~~~~~~~~~~~

With one exception, relations in the [kdcdefaults] section specify
default values for realm variables, to be used if the [realms]
subsection does not contain a relation for the tag.  See the
:ref:`kdc_realms` section for the definitions of these relations.

* **host_based_services**
* **kdc_ports**
* **kdc_tcp_ports**
* **no_host_referral**
* **restrict_anonymous_to_tgt**

**kdc_max_dgram_reply_size**
    Specifies the maximum packet size that can be sent over UDP.  The
    default value is 4096 bytes.


.. _kdc_realms:

[realms]
~~~~~~~~

Each tag in the [realms] section is the name of a Kerberos realm.
The value of the tag is a subsection where the relations define KDC
parameters for that particular realm.

For each realm, the following tags may be specified:

**acl_file**
    (String.)  Location of the access control list file that
    :ref:`kadmind(8)` uses to determine which principals are allowed
    which permissions on the Kerberos database.  The default value is
    |kdcdir|\ ``/kadm5.acl``.  For more information on Kerberos ACL
    file see :ref:`kadm5.acl(5)`.

**database_module**
    This relation indicates the name of the configuration section
    under :ref:`dbmodules` for database specific parameters used by
    the loadable database library.

**database_name**
    (String.)  This string specifies the location of the Kerberos
    database for this realm, if the DB2 back-end is being used.  If a
    **database_module** is specified for the realm and the
    corresponding module contains a **database_name** parameter, that
    value will take precedence over this one.  The default value is
    |kdcdir|\ ``/principal``.

**default_principal_expiration**
    (:ref:`abstime` string.)  Specifies the default expiration date of
    principals created in this realm.  The default value is 0, which
    means no expiration date.

**default_principal_flags**
    (Flag string.)  Specifies the default attributes of principals
    created in this realm.  The format for this string is a
    comma-separated list of flags, with '+' before each flag that
    should be enabled and '-' before each flag that should be
    disabled.  The **postdateable**, **forwardable**, **tgt-based**,
    **renewable**, **proxiable**, **dup-skey**, **allow-tickets**, and
    **service** flags default to enabled.

    There are a number of possible flags:

    **allow-tickets**
        Enabling this flag means that the KDC will issue tickets for
        this principal.  Disabling this flag essentially deactivates
        the principal within this realm.

    **dup-skey**
        Enabling this flag allows the principal to obtain a session
        key for another user, permitting user-to-user authentication
        for this principal.

    **forwardable**
        Enabling this flag allows the principal to obtain forwardable
        tickets.

    **hwauth**
        If this flag is enabled, then the principal is required to
        preauthenticate using a hardware device before receiving any
        tickets.

    **no-auth-data-required**
        Enabling this flag prevents PAC data from being added to
        service tickets for the principal.

    **ok-as-delegate**
        If this flag is enabled, it hints the client that credentials
        can and should be delegated when authenticating to the
        service.

    **ok-to-auth-as-delegate**
        Enabling this flag allows the principal to use S4USelf tickets.

    **postdateable**
        Enabling this flag allows the principal to obtain postdateable
        tickets.

    **preauth**
        If this flag is enabled on a client principal, then that
        principal is required to preauthenticate to the KDC before
        receiving any tickets.  On a service principal, enabling this
        flag means that service tickets for this principal will only
        be issued to clients with a TGT that has the preauthenticated
        bit set.

    **proxiable**
        Enabling this flag allows the principal to obtain proxy
        tickets.

    **pwchange**
        Enabling this flag forces a password change for this
        principal.

    **pwservice**
        If this flag is enabled, it marks this principal as a password
        change service.  This should only be used in special cases,
        for example, if a user's password has expired, then the user
        has to get tickets for that principal without going through
        the normal password authentication in order to be able to
        change the password.

    **renewable**
        Enabling this flag allows the principal to obtain renewable
        tickets.

    **service**
        Enabling this flag allows the the KDC to issue service tickets
        for this principal.

    **tgt-based**
        Enabling this flag allows a principal to obtain tickets based
        on a ticket-granting-ticket, rather than repeating the
        authentication process that was used to obtain the TGT.

**dict_file**
    (String.)  Location of the dictionary file containing strings that
    are not allowed as passwords.  If none is specified or if there is
    no policy assigned to the principal, no dictionary checks of
    passwords will be performed.

**host_based_services**
    (Whitespace- or comma-separated list.)  Lists services which will
    get host-based referral processing even if the server principal is
    not marked as host-based by the client.

**iprop_enable**
    (Boolean value.)  Specifies whether incremental database
    propagation is enabled.  The default value is false.

**iprop_master_ulogsize**
    (Integer.)  Specifies the maximum number of log entries to be
    retained for incremental propagation.  The maximum value is 2500;
    the default value is 1000.

**iprop_slave_poll**
    (Delta time string.)  Specifies how often the slave KDC polls for
    new updates from the master.  The default value is ``2m`` (that
    is, two minutes).

**iprop_port**
    (Port number.)  Specifies the port number to be used for
    incremental propagation.  This is required in both master and
    slave configuration files.

**iprop_resync_timeout**
    (Delta time string.)  Specifies the amount of time to wait for a
    full propagation to complete.  This is optional in configuration
    files, and is used by slave KDCs only.  The default value is 5
    minutes (``5m``).

**iprop_logfile**
    (File name.)  Specifies where the update log file for the realm
    database is to be stored.  The default is to use the
    **database_name** entry from the realms section of the krb5 config
    file, with ``.ulog`` appended.  (NOTE: If **database_name** isn't
    specified in the realms section, perhaps because the LDAP database
    back end is being used, or the file name is specified in the
    [dbmodules] section, then the hard-coded default for
    **database_name** is used.  Determination of the **iprop_logfile**
    default value will not use values from the [dbmodules] section.)

**kadmind_port**
    (Port number.)  Specifies the port on which the :ref:`kadmind(8)`
    daemon is to listen for this realm.  The assigned port for kadmind
    is 749, which is used by default.

**key_stash_file**
    (String.)  Specifies the location where the master key has been
    stored (via kdb5_util stash).  The default is |kdcdir|\
    ``/.k5.REALM``, where *REALM* is the Kerberos realm.

**kdc_ports**
    (Whitespace- or comma-separated list.)  Lists the ports on which
    the Kerberos server should listen for UDP requests, as a
    comma-separated list of integers.  The default value is
    ``88,750``, which are the assigned Kerberos port and the port
    historically used by Kerberos V4.

**kdc_tcp_ports**
    (Whitespace- or comma-separated list.)  Lists the ports on which
    the Kerberos server should listen for TCP connections, as a
    comma-separated list of integers.  If this relation is not
    specified, the compiled-in default is not to listen for TCP
    connections at all.

    If you wish to change this (note that the current implementation
    has little protection against denial-of-service attacks), the
    standard port number assigned for Kerberos TCP traffic is port 88.

**master_key_name**
    (String.)  Specifies the name of the principal associated with the
    master key.  The default is ``K/M``.

**master_key_type**
    (Key type string.)  Specifies the master key's key type.  The
    default value for this is |defmkey|.  For a list of all possible
    values, see :ref:`Encryption_and_salt_types`.

**max_life**
    (:ref:`duration` string.)  Specifies the maximum time period for
    which a ticket may be valid in this realm.  The default value is
    24 hours.

**max_renewable_life**
    (:ref:`duration` string.)  Specifies the maximum time period
    during which a valid ticket may be renewed in this realm.
    The default value is 0.

**no_host_referral**
    (Whitespace- or comma-separated list.)  Lists services to block
    from getting host-based referral processing, even if the client
    marks the server principal as host-based or the service is also
    listed in **host_based_services**.  ``no_host_referral = *`` will
    disable referral processing altogether.

**des_crc_session_supported**
    (Boolean value).  If set to true, the KDC will assume that service
    principals support des-cbc-crc for session key enctype negotiation
    purposes.  If **allow_weak_crypto** in :ref:`libdefaults` is
    false, or if des-cbc-crc is not a permitted enctype, then this
    variable has no effect.  Defaults to true.

**reject_bad_transit**
    (Boolean value.)  If set to true, the KDC will check the list of
    transited realms for cross-realm tickets against the transit path
    computed from the realm names and the capaths section of its
    :ref:`krb5.conf(5)` file; if the path in the ticket to be issued
    contains any realms not in the computed path, the ticket will not
    be issued, and an error will be returned to the client instead.
    If this value is set to false, such tickets will be issued
    anyways, and it will be left up to the application server to
    validate the realm transit path.

    If the disable-transited-check flag is set in the incoming
    request, this check is not performed at all.  Having the
    **reject_bad_transit** option will cause such ticket requests to
    be rejected always.

    This transit path checking and config file option currently apply
    only to TGS requests.

    The default value is true.

**restrict_anonymous_to_tgt**
    (Boolean value.)  If set to true, the KDC will reject ticket
    requests from anonymous principals to service principals other
    than the realm's ticket-granting service.  This option allows
    anonymous PKINIT to be enabled for use as FAST armor tickets
    without allowing anonymous authentication to services.  The
    default value is false.

**supported_enctypes**
    (List of *key*:*salt* strings.)  Specifies the default key/salt
    combinations of principals for this realm.  Any principals created
    through :ref:`kadmin(1)` will have keys of these types.  The
    default value for this tag is |defkeysalts|.  For lists of
    possible values, see :ref:`Encryption_and_salt_types`.


.. _dbdefaults:

[dbdefaults]
~~~~~~~~~~~~

The [dbdefaults] section specifies default values for some database
parameters, to be used if the [dbmodules] subsection does not contain
a relation for the tag.  See the :ref:`dbmodules` section for the
definitions of these relations.

* **ldap_kerberos_container_dn**
* **ldap_kdc_dn**
* **ldap_kadmind_dn**
* **ldap_service_password_file**
* **ldap_servers**
* **ldap_conns_per_server**


.. _dbmodules:

[dbmodules]
~~~~~~~~~~~

The [dbmodules] section contains parameters used by the KDC database
library and database modules.

The following tag may be specified in the [dbmodules] section:

**db_module_dir**
    This tag controls where the plugin system looks for modules.  The
    value should be an absolute path.

Other tags in the [dbmodules] section name a configuration subsection
for parameters which can be referred to by a realm's
**database_module** parameter.  The following tags may be specified in
the subsection:

**database_name**
    This DB2-specific tag indicates the location of the database in
    the filesystem.  The default is |kdcdir|\ ``/principal``.

**db_library**
    This tag indicates the name of the loadable database module.  The
    value should be ``db2`` for the DB2 module and ``kldap`` for the
    LDAP module.

**disable_last_success**
    If set to ``true``, suppresses KDC updates to the "Last successful
    authentication" field of principal entries requiring
    preauthentication.  Setting this flag may improve performance.
    (Principal entries which do not require preauthentication never
    update the "Last successful authentication" field.).  First
    introduced in version 1.9.

**disable_lockout**
    If set to ``true``, suppresses KDC updates to the "Last failed
    authentication" and "Failed password attempts" fields of principal
    entries requiring preauthentication.  Setting this flag may
    improve performance, but also disables account lockout.  First
    introduced in version 1.9.

**ldap_conns_per_server**
    This LDAP-specific tag indicates the number of connections to be
    maintained per LDAP server.

**ldap_kadmind_dn**
    This LDAP-specific tag indicates the default bind DN for the
    :ref:`kadmind(8)` daemon.  kadmind does a login to the directory
    as this object.  This object should have the rights to read and
    write the Kerberos data in the LDAP database.

**ldap_kdc_dn**
    This LDAP-specific tag indicates the default bind DN for the
    :ref:`krb5kdc(8)` daemon.  The KDC does a login to the directory
    as this object.  This object should have the rights to read the
    Kerberos data in the LDAP database, and to write data unless
    **disable_lockout** and **disable_last_success** are true.

**ldap_kerberos_container_dn**
    This LDAP-specific tag indicates the DN of the container object
    where the realm objects will be located.

**ldap_servers**
    This LDAP-specific tag indicates the list of LDAP servers that the
    Kerberos servers can connect to.  The list of LDAP servers is
    whitespace-separated.  The LDAP server is specified by a LDAP URI.
    It is recommended to use ``ldapi:`` or ``ldaps:`` URLs to connect
    to the LDAP server.

**ldap_service_password_file**
    This LDAP-specific tag indicates the file containing the stashed
    passwords (created by ``kdb5_ldap_util stashsrvpw``) for the
    **ldap_kadmind_dn** and **ldap_kdc_dn** objects.  This file must
    be kept secure.


.. _logging:

[logging]
~~~~~~~~~

The [logging] section indicates how :ref:`krb5kdc(8)` and
:ref:`kadmind(8)` perform logging.  The keys in this section are
daemon names, which may be one of:

**admin_server**
    Specifies how :ref:`kadmind(8)` performs logging.

**kdc**
    Specifies how :ref:`krb5kdc(8)` performs logging.

**default**
    Specifies how either daemon performs logging in the absence of
    relations specific to the daemon.

Values are of the following forms:

**FILE=**\ *filename* or **FILE:**\ *filename*
    This value causes the daemon's logging messages to go to the
    *filename*.  If the ``=`` form is used, the file is overwritten.
    If the ``:`` form is used, the file is appended to.

**STDERR**
    This value causes the daemon's logging messages to go to its
    standard error stream.

**CONSOLE**
    This value causes the daemon's logging messages to go to the
    console, if the system supports it.

**DEVICE=**\ *<devicename>*
    This causes the daemon's logging messages to go to the specified
    device.

**SYSLOG**\ [\ **:**\ *severity*\ [\ **:**\ *facility*\ ]]
    This causes the daemon's logging messages to go to the system log.

    The severity argument specifies the default severity of system log
    messages.  This may be any of the following severities supported
    by the syslog(3) call, minus the ``LOG_`` prefix: **EMERG**,
    **ALERT**, **CRIT**, **ERR**, **WARNING**, **NOTICE**, **INFO**,
    and **DEBUG**.

    The facility argument specifies the facility under which the
    messages are logged.  This may be any of the following facilities
    supported by the syslog(3) call minus the LOG\_ prefix: **KERN**,
    **USER**, **MAIL**, **DAEMON**, **AUTH**, **LPR**, **NEWS**,
    **UUCP**, **CRON**, and **LOCAL0** through **LOCAL7**.

    If no severity is specified, the default is **ERR**.  If no
    facility is specified, the default is **AUTH**.

In the following example, the logging messages from the KDC will go to
the console and to the system log under the facility LOG_DAEMON with
default severity of LOG_INFO; and the logging messages from the
administrative server will be appended to the file
``/var/adm/kadmin.log`` and sent to the device ``/dev/tty04``.

 ::

    [logging]
        kdc = CONSOLE
        kdc = SYSLOG:INFO:DAEMON
        admin_server = FILE:/var/adm/kadmin.log
        admin_server = DEVICE=/dev/tty04


PKINIT options
--------------

.. note::

          The following are pkinit-specific options.  These values may
          be specified in [kdcdefaults] as global defaults, or within
          a realm-specific subsection of [realms].  Also note that a
          realm-specific value over-rides, does not add to, a generic
          [kdcdefaults] specification.  The search order is:

1. realm-specific subsection of [realms],

    ::

       [realms]
           EXAMPLE.COM = {
               pkinit_anchors = FILE:/usr/local/example.com.crt
           }

2. generic value in the [kdcdefaults] section.

    ::

       [kdcdefaults]
           pkinit_anchors = DIR:/usr/local/generic_trusted_cas/

For information about the syntax of some of these options, see
:ref:`Specifying PKINIT identity information <pkinit_identity>` in
:ref:`krb5.conf(5)`.

**pkinit_anchors**
    Specifies the location of trusted anchor (root) certificates which
    the KDC trusts to sign client certificates.  This option is
    required if pkinit is to be supported by the KDC.  This option may
    be specified multiple times.

**pkinit_dh_min_bits**
    Specifies the minimum number of bits the KDC is willing to accept
    for a client's Diffie-Hellman key.  The default is 2048.

**pkinit_allow_upn**
    Specifies that the KDC is willing to accept client certificates
    with the Microsoft UserPrincipalName (UPN) Subject Alternative
    Name (SAN).  This means the KDC accepts the binding of the UPN in
    the certificate to the Kerberos principal name.  The default value
    is false.

    Without this option, the KDC will only accept certificates with
    the id-pkinit-san as defined in :rfc:`4556`.  There is currently
    no option to disable SAN checking in the KDC.

**pkinit_eku_checking**
    This option specifies what Extended Key Usage (EKU) values the KDC
    is willing to accept in client certificates.  The values
    recognized in the kdc.conf file are:

    **kpClientAuth**
        This is the default value and specifies that client
        certificates must have the id-pkinit-KPClientAuth EKU as
        defined in :rfc:`4556`.

    **scLogin**
        If scLogin is specified, client certificates with the
        Microsoft Smart Card Login EKU (id-ms-kp-sc-logon) will be
        accepted.

    **none**
        If none is specified, then client certificates will not be
        checked to verify they have an acceptable EKU.  The use of
        this option is not recommended.

**pkinit_identity**
    Specifies the location of the KDC's X.509 identity information.
    This option is required if pkinit is to be supported by the KDC.

**pkinit_kdc_ocsp**
    Specifies the location of the KDC's OCSP.

**pkinit_mapping_file**
    Specifies the name of the ACL pkinit mapping file.  This file maps
    principals to the certificates that they can use.

**pkinit_pool**
    Specifies the location of intermediate certificates which may be
    used by the KDC to complete the trust chain between a client's
    certificate and a trusted anchor.  This option may be specified
    multiple times.

**pkinit_revoke**
    Specifies the location of Certificate Revocation List (CRL)
    information to be used by the KDC when verifying the validity of
    client certificates.  This option may be specified multiple times.

**pkinit_require_crl_checking**
    The default certificate verification process will always check the
    available revocation information to see if a certificate has been
    revoked.  If a match is found for the certificate in a CRL,
    verification fails.  If the certificate being verified is not
    listed in a CRL, or there is no CRL present for its issuing CA,
    and **pkinit_require_crl_checking** is false, then verification
    succeeds.

    However, if **pkinit_require_crl_checking** is true and there is
    no CRL information available for the issuing CA, then verification
    fails.

    **pkinit_require_crl_checking** should be set to true if the
    policy is such that up-to-date CRLs must be present for every CA.


.. _Encryption_and_salt_types:

Encryption and salt types
-------------------------

Any tag in the configuration files which requires a list of encryption
types can be set to some combination of the following strings.
Encryption types marked as "weak" are available for compatibility but
not recommended for use.

==================================================== =========================================================
des-cbc-crc                                          DES cbc mode with CRC-32 (weak)
des-cbc-md4                                          DES cbc mode with RSA-MD4 (weak)
des-cbc-md5                                          DES cbc mode with RSA-MD5 (weak)
des-cbc-raw                                          DES cbc mode raw (weak)
des3-cbc-raw                                         Triple DES cbc mode raw (weak)
des3-cbc-sha1 des3-hmac-sha1 des3-cbc-sha1-kd        Triple DES cbc mode with HMAC/sha1
des-hmac-sha1                                        DES with HMAC/sha1 (weak)
aes256-cts-hmac-sha1-96 aes256-cts AES-256           CTS mode with 96-bit SHA-1 HMAC
aes128-cts-hmac-sha1-96 aes128-cts AES-128           CTS mode with 96-bit SHA-1 HMAC
arcfour-hmac rc4-hmac arcfour-hmac-md5               RC4 with HMAC/MD5
arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp   Exportable RC4 with HMAC/MD5 (weak)
camellia256-cts-cmac camellia256-cts                 Camellia-256 CTS mode with CMAC
camellia128-cts-cmac camellia128-cts                 Camellia-128 CTS mode with CMAC
des                                                  The DES family: des-cbc-crc, des-cbc-md5, and des-cbc-md4 (weak)
des3                                                 The triple DES family: des3-cbc-sha1
aes                                                  The AES family: aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96
rc4                                                  The RC4 family: arcfour-hmac
camellia                                             The Camellia family: camellia256-cts-cmac and camellia128-cts-cmac
==================================================== =========================================================

The string **DEFAULT** can be used to refer to the default set of
types for the variable in question.  Types or families can be removed
from the current list by prefixing them with a minus sign ("-").
Types or families can be prefixed with a plus sign ("+") for symmetry;
it has the same meaning as just listing the type or family.  For
example, "``DEFAULT -des``" would be the default set of encryption
types with DES types removed, and "``des3 DEFAULT``" would be the
default set of encryption types with triple DES types moved to the
front.

While **aes128-cts** and **aes256-cts** are supported for all Kerberos
operations, they are not supported by very old versions of our GSSAPI
implementation (krb5-1.3.1 and earlier).  Services running versions of
krb5 without AES support must not be given AES keys in the KDC
database.

Kerberos keys for users are usually derived from passwords.  To ensure
that people who happen to pick the same password do not have the same
key, Kerberos 5 incorporates more information into the key using
something called a salt.  The supported salt types are as follows:

================= ============================================
normal            default for Kerberos Version 5
v4                the only type used by Kerberos Version 4 (no salt)
norealm           same as the default, without using realm information
onlyrealm         uses only realm information as the salt
afs3              AFS version 3, only used for compatibility with Kerberos 4 in AFS
special           generate a random salt
================= ============================================


Sample kdc.conf File
--------------------

Here's an example of a kdc.conf file:

 ::

    [kdcdefaults]
        kdc_ports = 88

    [realms]
        ATHENA.MIT.EDU = {
            kadmind_port = 749
            max_life = 12h 0m 0s
            max_renewable_life = 7d 0h 0m 0s
            master_key_type = des3-hmac-sha1
            supported_enctypes = des3-hmac-sha1:normal des-cbc-crc:normal des-cbc-crc:v4
            database_module = openldap_ldapconf
        }

    [logging]
        kdc = FILE:/usr/local/var/krb5kdc/kdc.log
        admin_server = FILE:/usr/local/var/krb5kdc/kadmin.log

    [dbdefaults]
        ldap_kerberos_container_dn = cn=krbcontainer,dc=mit,dc=edu

    [dbmodules]
        openldap_ldapconf = {
            db_library = kldap
            disable_last_success = true
            ldap_kdc_dn = "cn=krbadmin,dc=mit,dc=edu"
                # this object needs to have read rights on
                # the realm container and principal subtrees
            ldap_kadmind_dn = "cn=krbadmin,dc=mit,dc=edu"
                # this object needs to have read and write rights on
                # the realm container and principal subtrees
            ldap_service_password_file = /etc/kerberos/service.keyfile
            ldap_servers = ldaps://kerberos.mit.edu
            ldap_conns_per_server = 5
        }


FILES
------

|kdcdir|\ ``/kdc.conf``


SEE ALSO
---------

:ref:`krb5.conf(5)`, :ref:`krb5kdc(8)`, :ref:`kadm5.acl(5)`
