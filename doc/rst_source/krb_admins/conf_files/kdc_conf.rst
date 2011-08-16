.. _kdc.conf:

kdc.conf
==============

The kdc.conf file contains KDC configuration information, including defaults used when issuing Kerberos tickets. Normally, you should install your kdc.conf file in the directory */usr/local/var/krb5kdc*. You can override the default location by setting the environment variable *KRB5_KDC_PROFILE*.

Structure
--------------

The kdc.conf file is set up in the same format as the :ref:`krb5.conf` file. The kdc.conf file may contain any or all of the following three sections:

==================== ================================
:ref:`kdcdefaults`        Contains default values for overall behavior of the KDC.
:ref:`kdc_realms`             Contains subsections keyed by Kerberos realm names. Each subsection describes realm-specific information, including where to find the Kerberos servers for that realm.
:ref:`kdc_logging`            Contains relations which determine how Kerberos programs are to perform logging. 
==================== ================================

Sections
-------------


.. _kdcdefaults:

**[kdcdefaults]**
~~~~~~~~~~~~~~~~~~~~~~~

The following relation is defined in the [kdcdefaults] section:

**host_based_services**
    This relation lists the services that will get host-based referral processing even if the server principal is not marked as host-based by the client.
**kdc_max_dgram_reply_size**
    Specifes the maximum packet size that can be sent over UDP. The default value is 4096 bytes.
**kdc_ports**
    This relation lists the ports on which the Kerberos server should listen for UDP requests by default. This list is a comma separated list of integers. If this relation is not specified, the compiled-in default is 88,750, the first being the assigned Kerberos port and the second which was used by Kerberos V4. 
**kdc_tcp_ports**
    This relation lists the ports on which the Kerberos server should listen for TCP connections by default. This list is a comma separated list of integers. If this relation is not specified, the compiled-in default is not to listen for TCP connections at all.

    If you wish to change this (which we do not recommend, because the current implementation has little protection against denial-of-service attacks), the standard port number assigned for Kerberos TCP traffic is port 88. 
**no_host_referral**
    This relation blocks the specified services from host-based referral processing, even if the client marks the server principal as host-based or the service is also listed in *host_based_services*. *no_host_referral* = \*  will disable referral processing altogether.
**restrict_anonymous_to_tgt**
    This flag determines the default value of restrict_anonymous_to_tgt for realms. The default value is false. 


.. _kdc_realms:

**[realms]**
~~~~~~~~~~~~~~~

Each tag in the [realms] section of the file names a Kerberos realm. The value of the tag is a subsection where the relations in that subsection define KDC parameters for that particular realm.

For each realm, the following tags may be specified in the [realms] subsection:

**acl_file**
    (String.) Location of the access control list (acl) file that kadmin uses to determine which principals are allowed which permissions on the database. The default is */usr/local/var/krb5kdc/kadm5.acl*. 
**admin_keytab**
    (String.) Location of the keytab file that the legacy administration daemons kadmind4 and v5passwdd use to authenticate to the database. The default is */usr/local/var/krb5kdc/kadm5.keytab*. 
**database_name**
    This string specifies the location of the Kerberos database for this realm.
**default_principal_expiration**
    (Absolute time string.) Specifies the default expiration date of principals created in this realm. The default value for this tag is 0. 
**default_principal_flags**
    (Flag string.) Specifies the default attributes of principals created in this realm. The format for this string is a comma-separated list of flags, with '+' before each flag that should be enabled and '-' before each flag that should be disabled. The default is *postdateable, forwardable, tgt-based, renewable, proxiable, dup-skey, allow-tickets*, and *service enabled*.

    There are a number of possible flags:

    *allow-tickets*
        Enabling this flag means that the KDC will issue tickets for this principal. Disabling this flag essentially deactivates the principal within this realm. 
    *dup-skey*
        Enabling this flag allows the principal to obtain a session key for another user, permitting user-to-user authentication for this principal. 
    *forwardable*
        Enabling this flag allows the principal to obtain forwardable tickets. 
    *hwauth*
        If this flag is enabled, then the principal is required to preauthenticate using a hardware device before receiving any tickets. 
    *no-auth-data-required*
        Enabling this flag prvents PAC data from being added to the service tickets. 
    *ok-as-delegate*
        If this flag is enabled, it hints the client that credentials can and should be delegated when authenticating to the service.      
    *ok-to-auth-as-delegate*
        Enabling this flag allows the principal to use S4USelf ticket.
    *postdateable*
        Enabling this flag allows the principal to obtain postdateable tickets. 
    *preauth*
        If this flag is enabled on a client principal, then that principal is required to preauthenticate to the KDC before receiving any tickets. On a service principal, enabling this flag means that service tickets for this principal will only be issued to clients with a TGT that has the preauthenticated ticket set. 
    *proxiable*
        Enabling this flag allows the principal to obtain proxy tickets. 
    *pwchange*
        Enabling this flag forces a password change for this principal. 
    *pwservice*
        If this flag is enabled, it marks this principal as a password change service. This should only be used in special cases, for example, if a user's password has expired, then the user has to get tickets for that principal without going through the normal password authentication in order to be able to change the password. 
    *renewable*
        Enabling this flag allows the principal to obtain renewable tickets. 
    *service*
        Enabling this flag allows the the KDC to issue service tickets for this principal. 
    *tgt-based*
        Enabling this flag allows a principal to obtain tickets based on a ticket-granting-ticket, rather than repeating the authentication process that was used to obtain the TGT. 

**dict_file**
    (String.) Location of the dictionary file containing strings that are not allowed as passwords. If none is specified or if there is no policy assigned to the principal, no dictionary checks of passwords will be performed. 
**host_based_services**
    (Whitespace- or comma-separated list) This relation lists the services that will get host-based referral processing even if the server principal is not marked as host-based by the client.
**iprop_enable**
    This boolean ("true" or "false") specifies whether incremental database propagation is enabled.  The default is "false".
**iprop_master_ulogsize**
    This numeric value specifies the maximum number of log entries to be retained for incremental propagation.  The maximum value is 2500; default is 1000.
**iprop_slave_poll**
    This delta time string specfies how often the slave KDC polls for new updates from the master.  Default is "2m" (that is, two minutes).
**iprop_port**
    (Port number.) This specifies the port number to be used for incremental propagation. This is required in both master and slave configuration files. 
**iprop_logfile**
    (File name) This specifies where the update log file for the realm database is to be stored. The default is to use the *database_name* entry from the realms section of the krb5 config file, with *.ulog* appended. (NOTE: If *database_name* isn't specified in the realms section, perhaps because the LDAP database back end is being used, or the file name is specified in the *dbmodules* section, then the hard-coded default for *database_name* is used. Determination of the *iprop_logfile* default value will not use values from the *dbmodules* section.) 
**kadmind_port**
    (Port number.) Specifies the port on which the kadmind daemon is to listen for this realm. The assigned port for kadmind is 749. 
**key_stash_file**
    (String.) Specifies the location where the master key has been stored (via kdb5_util stash). The default is /usr/local/var/krb5kdc/.k5.REALM, where REALM is the Kerberos realm. 
**kdc_ports**
    (String.) Specifies the list of ports that the KDC is to listen to for UDP requests for this realm. By default, the value of kdc_ports as specified in the [kdcdefaults] section is used. 
**kdc_tcp_ports**
    (String.) Specifies the list of ports that the KDC is to listen to for TCP requests for this realm. By default, the value of kdc_tcp_ports as specified in the [kdcdefaults] section is used. 
**master_key_name**
    (String.) Specifies the name of the principal associated with the master key. The default is K/M. 
**master_key_type**
    (Key type string.) Specifies the master key's key type. The default value for this is des3-cbc-sha1. For a list of all possible values, see :ref:`Supported_Encryption_Types_and_Salts`. 
**max_life**
    (Delta time string.) Specifes the maximum time period for which a ticket may be valid in this realm. The default value is 24 hours. 
**max_renewable_life**
    (Delta time string.) Specifies the maximum time period during which a valid ticket may be renewed in this realm. The default value is 0. 
**no_host_referral**
    (Whitespace- or comma-separated list) This relation blocks the specified services from host-based referral processing, even if the client marks the server principal as host-based or the service is also listed in *host_based_services*. *no_host_referral* = \*  will disable referral processing altogether.
**reject_bad_transit**
    A boolean value (true, false). If set to true, the KDC will check the list of transited realms for cross-realm tickets against the transit path computed from the realm names and the capaths section of its krb5.conf file; if the path in the ticket to be issued contains any realms not in the computed path, the ticket will not be issued, and an error will be returned to the client instead. If this value is set to false, such tickets will be issued anyways, and it will be left up to the application server to validate the realm transit path.

    If the disable-transited-check flag is set in the incoming request, this check is not performed at all. Having the reject_bad_transit option will cause such ticket requests to be rejected always.

    This transit path checking and config file option currently apply only to TGS requests.

    Earlier versions of the MIT release (before 1.2.3) had bugs in the application server support such that the server-side checks may not be performed correctly. We recommend turning this option on, unless you know that all application servers in this realm have been updated to fixed versions of the software, and for whatever reason, you don't want the KDC to do the validation.

    This is a per-realm option so that multiple-realm KDCs may control it separately for each realm, in case (for example) one realm has had the software on its application servers updated but another has not.

    This option defaults to true. 
**restrict_anonymous_to_tgt**
    A boolean value (true, false). If set to true, the KDC will reject ticket requests from anonymous principals to service principals other than the realm's ticket-granting service. This option allows anonymous PKINIT to be enabled for use as FAST armor tickets without allowing anonymous authentication to services. By default, the value of restrict_anonymous_to_tgt as specified in the [kdcdefaults] section is used. 

**supported_enctypes**
    List of key:salt strings. Specifies the default key/salt combinations of principals for this realm. Any principals created through kadmin will have keys of these types. The default value for this tag is aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal des3-cbc-sha1:normal arcfour-hmac-md5:normal. For lists of possible values, see :ref:`Supported_Encryption_Types_and_Salts` 




.. _kdc_logging:

**[logging]**
~~~~~~~~~~~~~~~~~~~~

See :ref:`logging` section in :ref:`krb5.conf` 


PKINIT options
---------------

.. note:: The following are pkinit-specific options. Note that these values may be specified in [kdcdefaults] as global defaults, or within a realm-specific subsection of [realms]. Also note that a realm-specific value over-rides, does not add to, a generic [kdcdefaults] specification. The search order is:

   1. realm-specific subsection of [realms]

                [realms]
                    EXAMPLE.COM = {
                        pkinit_anchors = FILE\:/usr/local/example.com.crt

                    }
                

   2. generic value in the [kdcdefaults] section.

                [kdcdefaults]
                    pkinit_anchors = DIR\:/usr/local/generic_trusted_cas/
                


For information about the syntax of some of these options, see See pkinit identity syntax.

**pkinit_anchors**
    Specifies the location of trusted anchor (root) certificates which the KDC trusts to sign client certificates. This option is required if pkinit is to be supported by the KDC. This option may be specified multiple times.

**pkinit_dh_min_bits**
    Specifies the minimum number of bits the KDC is willing to accept for a client's Diffie-Hellman key. The default is 2048.

**pkinit_allow_upn**
    Specifies that the KDC is willing to accept client certificates with the Microsoft UserPrincipalName (UPN) Subject Alternative Name (SAN). This means the KDC accepts the binding of the UPN in the certificate to the Kerberos principal name.

    The default is *false*.

    Without this option, the KDC will only accept certificates with the *id-pkinit-san* as defined in :rfc:`4556`. There is currently no option to disable SAN checking in the KDC.

**pkinit_eku_checking**
    This option specifies what Extended Key Usage (EKU) values the KDC is willing to accept in client certificates. The values recognized in the kdc.conf file are:

    *kpClientAuth*
        This is the default value and specifies that client certificates must have the id-pkinit-KPClientAuth EKU as defined in :rfc:`4556`.
    *scLogin*
        If scLogin is specified, client certificates with the Microsoft Smart Card Login EKU (id-ms-kp-sc-logon) will be accepted.
    *none*
        If none is specified, then client certificates will not be checked to verify they have an acceptable EKU. The use of this option is not recommended. 

**pkinit_identity**
    Specifies the location of the KDC's X.509 identity information. This option is required if pkinit is to be supported by the KDC.

**pkinit_kdc_ocsp**
    Specifies the location of the KDC's OCSP.

**pkinit_mapping_file**
    Specifies the name of the ACL pkinit mapping file. This file maps principals to the certificates that they can use.
 
**pkinit_pool**
    Specifies the location of intermediate certificates which may be used by the KDC to complete the trust chain between a client's certificate and a trusted anchor. This option may be specified multiple times.

**pkinit_revoke**
    Specifies the location of Certificate Revocation List (CRL) information to be used by the KDC when verifying the validity of client certificates. This option may be specified multiple times.

**pkinit_require_crl_checking**
    The default certificate verification process will always check the available revocation information to see if a certificate has been revoked. If a match is found for the certificate in a CRL, verification fails. If the certificate being verified is not listed in a CRL, or there is no CRL present for its issuing CA, and pkinit_require_crl_checking is false, then verification succeeds.

    However, if pkinit_require_crl_checking is true and there is no CRL information available for the issuing CA, then verification fails.

    *pkinit_require_crl_checking* should be set to true if the policy is such that up-to-date CRLs must be present for every CA.


Sample kdc.conf File
--------------------

Here's an example of a kdc.conf file::

     [kdcdefaults]
         kdc_ports = 88
     
     [realms]
         ATHENA.MIT.EDU = {
             kadmind_port = 749
             max_life = 12h 0m 0s
             max_renewable_life = 7d 0h 0m 0s
             master_key_type = des3-hmac-sha1
             supported_enctypes = des3-hmac-sha1:normal des-cbc-crc:normal des-cbc-crc:v4
         }
     
     [logging]
         kdc = FILE:/usr/local/var/krb5kdc/kdc.log
         admin_server = FILE:/usr/local/var/krb5kdc/kadmin.log
     

FILES
------
       
/usr/local/var/krb5kdc/kdc.conf

SEE ALSO
---------

krb5.conf(5), krb5kdc(8)


