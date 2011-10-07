.. _krb5.conf:

krb5.conf
==========

The krb5.conf file contains Kerberos configuration information, including the locations of KDCs and admin servers for the Kerberos realms of interest, defaults for the current realm and for Kerberos applications, and mappings of hostnames onto Kerberos realms. Normally, you should install your krb5.conf file in the directory /etc. You can override the default location by setting the environment variable KRB5_CONFIG.

Structure
---------

The krb5.conf file is set up in the style of a Windows INI file. Sections are headed by the section name, in square brackets. Each section may contain zero or more relations, of the form::

     foo = bar
     

or ::

     fubar = {
             foo = bar
             baz = quux
     }
     

Placing a '\*' at the end of a line indicates that this is the *final* value for the tag. This means that neither the remainder of this configuration file nor any other configuration file will be checked for any other values for this tag.

For example, if you have the following lines::

     foo = bar*
     foo = baz
     

then the second value of *foo* (baz) would never be read.

The krb5.conf file can include other files using either of the following directives at the beginning of a line::

     include FILENAME
     includedir DIRNAME
     

*FILENAME* or *DIRNAME* should be an absolute path. The named file or directory must exist and be readable. Including a directory includes all files within the directory whose names consist solely of alphanumeric characters, dashes, or underscores. Included profile files are syntactically independent of their parents, so each included file must begin with a section header.

The krb5.conf file can specify that configuration should be obtained from a loadable module, rather than the file itself, using the following directive at the beginning of a line before any section headers::

     module MODULEPATH:RESIDUAL

*MODULEPATH* may be relative to the library path of the krb5 installation, or it may be an absolute path.  *RESIDUAL* is provided to the module at initialization time.  If krb5.conf uses a module directive, kdc.conf should also use one if it exists.

The krb5.conf file may contain any or all of the following sections:

============== =======================================================
libdefaults_   Contains default values used by the Kerberos V5 library. 
realms_        Contains subsections keyed by Kerberos realm names. Each subsection describes realm-specific information, including where to find the Kerberos servers for that realm. 
domain_realm_  Contains relations which map domain names and subdomains onto Kerberos realm names. This is used by programs to determine what realm a host should be in, given its fully qualified domain name. 
logging_       Contains relations which determine how Kerberos programs are to perform logging. 
capaths_       Contains the authentication paths used with direct (nonhierarchical) cross-realm authentication. Entries in this section are used by the client to determine the intermediate realms which may be used in cross-realm authentication. It is also used by the end-service when checking the transited field for trusted intermediate realms. 
plugins_       Contains tags to register dynamic plugin modules and to turn modules on and off. 
appdefaults_   Contains default values that can be used by Kerberos V5 applications. 
============== =======================================================

Sections
----------


.. _libdefaults:

**[libdefaults]** 
~~~~~~~~~~~~~~~~~~~

The libdefaults section may contain any of the following relations:

**allow_weak_crypto**
    If this is set to 0 (for false), then weak encryption types will be filtered out of the previous three lists (as noted in :ref:`Supported_Encryption_Types_and_Salts`). The default value for this tag is false, which may cause authentication failures in existing Kerberos infrastructures that do not support strong crypto. Users in affected environments should set this tag to true until their infrastructure adopts stronger ciphers. 

**ap_req_checksum_type**
     An integer which specifies the type of AP-REQ checksum to use in authenticators. 
     This variable should be unset so the appropriate checksum for the encryption key in use will be used.   
     This can be set if backward compatibility requires a specific checksum type.
     See the *kdc_req_checksum_type* configuration option for the possible values and their meanings. 

**canonicalize**
    This flag indicates to the KDC that the client is prepared to receive a reply that contains a principal name other than the one requested.
    The client should expect, when sending names with the "canonicalize" KDC option,
    that names in the KDC's reply will be different than the name in the request.
    The default value for this flag is not set. 

**ccache_type**
    Use this parameter on systems which are DCE clients, to specify the type of cache to be created by kinit, or when forwarded tickets are received. DCE and Kerberos can share the cache, but some versions of DCE do not support the default cache as created by this version of Kerberos. Use a value of 1 on DCE 1.0.3a systems, and a value of 2 on DCE 1.1 systems. The default value is 4. 

**clockskew**
    Sets the maximum allowable amount of clockskew in seconds that the library will tolerate before assuming that a Kerberos message is invalid. The default value is 300 seconds, or five minutes. 

**default_keytab_name**
    This relation specifies the default keytab name to be used by application servers such as telnetd and rlogind. The default is */etc/krb5.keytab*. 

**default_realm**
    Identifies the default Kerberos realm for the client. Set its value to your Kerberos realm. If this is not specified and the TXT record lookup is enabled (see :ref:`udns_label`), then that information will be used to determine the default realm. If this tag is not set in this configuration file and there is no DNS information found, then an error will be returned. 

**default_tgs_enctypes**
    Identifies the supported list of session key encryption types that should be returned by the KDC. The list may be delimited with commas or whitespace. Kerberos supports many different encryption types, and support for more is planned in the future. (see :ref:`Supported_Encryption_Types_and_Salts` for a list of the accepted values for this tag). The default value is *aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 des-cbc-crc des-cbc-md5 des-cbc-md4*.

**default_tkt_enctypes**
    Identifies the supported list of session key encryption types that should be requested by the client. The format is the same as for default_tgs_enctypes. The default value for this tag is *aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 des-cbc-crc des-cbc-md5 des-cbc-md4*. 

**dns_fallback**
    General flag controlling the use of DNS for Kerberos information. If both of the preceding options are specified, this option has no effect. 

**dns_lookup_kdc**
    Indicate whether DNS SRV records should be used to locate the KDCs and other servers for a realm, if they are not listed in the information for the realm. (Note that the admin_server entry must be in the file, because the DNS implementation for it is incomplete.)

    Enabling this option does open up a type of denial-of-service attack, if someone spoofs the DNS records and redirects you to another server. However, it's no worse than a denial of service, because that fake KDC will be unable to decode anything you send it (besides the initial ticket request, which has no encrypted data), and anything the fake KDC sends will not be trusted without verification using some secret that it won't know.

    If this option is not specified but dns_fallback is, that value will be used instead. If neither option is specified, the behavior depends on configure-time options; if none were given, the default is to enable this option. If the DNS support is not compiled in, this entry has no effect. 

**dns_lookup_realm**
    Indicate whether DNS TXT records should be used to determine the Kerberos realm of a host.

    Enabling this option may permit a redirection attack, where spoofed DNS replies persuade a client to authenticate to the wrong realm, when talking to the wrong host (either by spoofing yet more DNS records or by intercepting the net traffic). Depending on how the client software manages hostnames, however, it could already be vulnerable to such attacks. We are looking at possible ways to minimize or eliminate this exposure. For now, we encourage more adventurous sites to try using Secure DNS.

    If this option is not specified but dns_fallback is, that value will be used instead. If neither option is specified, the behavior depends on configure-time options; if none were given, the default is to disable this option. If the DNS support is not compiled in, this entry has no effect. 

**extra_addresses**
    This allows a computer to use multiple local addresses, in order to allow Kerberos to work in a network that uses NATs. The addresses should be in a comma-separated list. 

**forwardable**
    If this flag is set, initial tickets by default will be forwardable. The default value for this flag is not set. 

**ignore_acceptor_hostname**
    When accepting GSSAPI or krb5 security contexts for host-based service principals, 
    ignore any hostname passed by the calling application and allow any service principal present in the keytab 
    which matches the service name and realm  name (if given).  
    This option can improve the administrative flexibility of server applications on multihomed hosts, 
    but can compromise the security of virtual hosting environments.  The default value is false.

**k5login_authoritative**
    If the value of this relation is true (the default), principals must be listed in a local user's k5login file to be granted login access, if a k5login file exists. If the value of this relation is false, a principal may still be granted login access through other mechanisms even if a k5login file exists but does not list the principal. 

**k5login_directory**
    If set, the library will look for a local user's k5login file within the named directory, with a filename corresponding to the local username. If not set, the library will look for k5login files in the user's home directory, with the filename .k5login. For security reasons, k5login files must be owned by the local user or by root. 

**kdc_default_options**
   Default KDC options (Xored for multiple values) when requesting initial credentials. By default it is set to 0x00000010 (KDC_OPT_RENEWABLE_OK).

**kdc_timesync**
    If this is set to 1 (for true), then client machines will compute the difference between their time and the time returned by the KDC in the timestamps in the tickets and use this value to correct for an inaccurate system clock. This corrective factor is only used by the Kerberos library. The default is 1. 

**kdc_req_checksum_type**
    An integer which specifies the type of checksum to use for the KDC requests for compatibility with DCE security servers 
    which do not support the default RSA MD5 used by Kerberos V5.
    This applies to DCE 1.1 and earlier.
    Use a value of 2 to use the RSA MD4 instead. 
    This value is only used for DES keys; other keys use the preferred checksum type for those keys.

    The possible values and their meanings are as follows.

    ======== ===============================
    1        CRC32
    2        RSA MD4
    3        RSA MD4 DES
    4        DES CBC
    7        RSA MD5
    8        RSA MD5 DES
    9        NIST SHA
    12       HMAC SHA1 DES3
    -138     Microsoft MD5 HMAC checksum type 
    ======== ===============================


**noaddresses**
    Setting this flag causes the initial Kerberos ticket to be addressless. The default for the flag is set. 

**permitted_enctypes**
    Identifies all encryption types that are permitted for use in session key encryption. The default value for this tag is *aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 des-cbc-crc des-cbc-md5 des-cbc-md4*. 

**plugin_base_dir**
    If set, determines the base directory where krb5 plugins are located.  
    The default value is  the  "krb5/plugins" subdirectory of the krb5 library directory.


**preferred_preauth_types**
    This allows you to set the preferred preauthentication types which the client will attempt before others which may be advertised by a KDC.  The default value for this setting is "17, 16, 15, 14", which forces libkrb5 to attempt to use PKINIT if it is supported.

**proxiable**
    If this flag is set, initial tickets by default will be proxiable. The default value for this flag is not set. 

**rdns**
    If set to false, prevent the use of reverse DNS resolution when translating hostnames into service principal names. Defaults to true. Setting this flag to false is more secure, but may force users to exclusively use fully qualified domain names when authenticating to services. 

**realm_try_domains**
    Indicate whether a host's domain components should be used to determine the Kerberos realm of the host.  The value of this variable is an integer: -1 means not to search, 0 means to try the host's domain itself, 1 means to also try the domain's immediate parent, and so forth. The library's usual mechanism for locating Kerberos realms is used to determine whether a domain is a valid realm--which may involve consulting DNS if *dns_lookup_kdc* is set.  The default is not to search domain components.

**renew_lifetime**
    The value of this tag is the default renewable lifetime for initial tickets. The default value for the tag is 0. 

**safe_checksum_type**

    An integer which specifies the type of checksum to use for the KRB-SAFE requests.  By default it is set to 8 (RSA MD5 DES). 
    For compatibility with applications linked against DCE version 1.1 or earlier Kerberos libraries, 
    use a value of 3 to use the RSA MD4 DES instead.  
    This field is ignored when its value is incompatible with the session key type.
    See the *kdc_req_checksum_type* configuration option for the possible values and their meanings. 

**ticket_lifetime**
    The value of this tag is the default lifetime for initial tickets. The default value for the tag is 1 day. 

**udp_preference_limit**
    When sending a message to the KDC, the library will try using TCP before UDP if the size of the message is above *udp_preference_list*. If the message is smaller than *udp_preference_list*, then UDP will be tried before TCP. Regardless of the size, both protocols will be tried if the first attempt fails. 
**verify_ap_req_nofail**
    If this flag is set, then an attempt to get initial credentials will fail if the client machine does not have a keytab. The default for the flag is not set. 

.. _realms:

**[realms]**
~~~~~~~~~~~~~~~~~

Each tag in the [realms] section of the file is the name of a Kerberos realm. The value of the tag is a subsection with relations that define the properties of that particular realm. For each realm, the following tags may be specified in the realm's subsection:


**admin_server**
    Identifies the host where the administration server is running. Typically, this is the master Kerberos server. This tag must be given a value in order to communicate with the kadmin server for the realm. 

**auth_to_local**
    This tag allows you to set a general rule for mapping principal names to local user names. It will be used if there is not an explicit mapping for the principal name that is being translated. The possible values are:


    DB:filename
        The principal will be looked up in the database filename. Support for this is not currently compiled in by default.
    RULE:exp
        The local name will be formulated from exp.

        The format for exp is [n:string](regexp)s/pattern/replacement/g. The integer n indicates how many components the target principal should have. If this matches, then a string will be formed from string, substituting the realm of the principal for $0 and the n'th component of the principal for $n (e.g. if the principal was *johndoe/admin* then [2:$2$1foo] would result in the string "adminjohndoefoo"). If this string matches regexp, then the s//[g] substitution command will be run over the string. The optional g will cause the substitution to be global over the string, instead of replacing only the first match in the string.

    DEFAULT
        The principal name will be used as the local user name. If the principal has more than one component or is not in the default realm, this rule is not applicable and the conversion will fail. 

    For example::

              [realms]
                  ATHENA.MIT.EDU = {
                      auth_to_local = RULE:[2:$1](johndoe)s/^.*$/guest/
                      auth_to_local = RULE:[2:$1;$2](^.*;admin$)s/;admin$//
                      auth_to_local = RULE:[2:$2](^.*;root)s/^.*$/root/
                      auto_to_local = DEFAULT
                  }
              

    would result in any principal without *root* or *admin* as the second component to be translated with the default rule. A principal with a second component of *admin* will become its first component. *root* will be used as the local name for any principal with a second component of *root*. The exception to these two rules are any principals *johndoe*/\*, which will always get the local name *guest*. 

**auth_to_local_names**
    This subsection allows you to set explicit mappings from principal names to local user names. The tag is the mapping name, and the value is the corresponding local user name. 

**database_module**
    This relation indicates the name of the configuration section under [dbmodules] for database specific parameters used by the loadable database library. 

**default_domain**
    This tag is used for Kerberos 4 compatibility. Kerberos 4 does not require the entire hostname of a server to be in its principal like Kerberos 5 does. This tag provides the domain name needed to produce a full hostname when translating V4 principal names into V5 principal names. All servers in this realm are assumed to be in the domain given as the value of this tag 

**kdc**
    The name or address of a host running a KDC for that realm. An optional port number, separated from the hostname by a colon, may be included. If the name or address contains colons (for example, if it is an IPv6 address), enclose it in square brackets to distinguish the colon from a port separator. For your computer to be able to communicate with the KDC for each realm, this tag must be given a value in each realm subsection in the configuration file, or there must be DNS SRV records specifying the KDCs (see :ref:`udns_label`). 

**kpasswd_server** 
    Points to the server where all the password changes are performed.  If there is no such entry, the port 464 on the *admin_server* host will be tried.  
                                 
**krb524_server** 
    Points to the server that does 524 conversions.  If it is not mentioned, the krb524 port 4444 on the kdc will be tried.

**master_kdc**
    Identifies the master KDC(s). Currently, this tag is used in only one case: If an attempt to get credentials fails because of an invalid password, the client software will attempt to contact the master KDC, in case the user's password has just been changed, and the updated database has not been propagated to the slave servers yet. 

**v4_instance_convert**
    This subsection allows the administrator to configure exceptions to the default_domain mapping rule. It contains V4 instances (the tag name) which should be translated to some specific hostname (the tag value) as the second component in a Kerberos V5 principal name. 

**v4_realm**
    This relation is used by the krb524 library routines when converting a V5 principal name to a V4 principal name. It is used when the V4 realm name and the V5 realm name are not the same, but still share the same principal names and passwords. The tag value is the Kerberos V4 realm name. 

.. _domain_realm:

**[domain_realm]**
~~~~~~~~~~~~~~~~~~~~~

The [domain_realm] section provides a translation from a domain name or hostname to a Kerberos realm name. The tag name can be a host name, or a domain name, where domain names are indicated by a prefix of a period (.). The value of the relation is the Kerberos realm name for that particular host or domain. Host names and domain names should be in lower case.

If no translation entry applies, the host's realm is considered to be the hostname's domain portion converted to upper case. For example, the following [domain_realm] section::

     [domain_realm]
         crash.mit.edu = TEST.ATHENA.MIT.EDU
         .mit.edu = ATHENA.MIT.EDU
         mit.edu = ATHENA.MIT.EDU
         example.com = EXAMPLE.COM
     

maps the host with the *exact* name *crash.mit.edu* into the TEST.ATHENA.MIT.EDU realm. The period prefix in *.mit.edu* denotes that *all* systems in the *mit.edu* domain belong to  ATHENA.MIT.EDU realm.
Note the entries for the hosts *mit.edu* and *example.com*. Without these entries, these hosts would be mapped into the Kerberos realms EDU and COM, respectively.

.. _logging:

**[logging]**
~~~~~~~~~~~~~~~~~~~~~~~

The [logging] section indicates how a particular entity is to perform its logging. The relations in this section assign one or more values to the entity name. Currently, the following entities are used:

**admin_server**
    These entries specify how the administrative server is to perform its logging. 
**default**
    These entries specify how to perform logging in the absence of explicit specifications otherwise. 
**kdc**
    These entries specify how the KDC is to perform its logging. 

Values are of the following forms:

| FILE=<filename>
| FILE:<filename>

    This value causes the entity's logging messages to go to the specified file. If the = form is used, the file is overwritten. If the \: form is used, the file is appended to. 

STDERR
    This value causes the entity's logging messages to go to its standard error stream. 
CONSOLE
    This value causes the entity's logging messages to go to the console, if the system supports it. 
DEVICE=<devicename>
    This causes the entity's logging messages to go to the specified device. 
SYSLOG[:<severity>[:<facility>]]
    This causes the entity's logging messages to go to the system log.

    The severity argument specifies the default severity of system log messages. This may be any of the following severities supported by the syslog(3) call, minus the LOG\_ prefix: LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, and LOG_DEBUG. For example, a value of CRIT would specify LOG_CRIT severity.

    The facility argument specifies the facility under which the messages are logged. This may be any of the following facilities supported by the syslog(3) call minus the LOG\_ prefix: LOG_KERN, LOG_USER, LOG_MAIL, LOG_DAEMON, LOG_AUTH, LOG_LPR, LOG_NEWS, LOG_UUCP, LOG_CRON, and LOG_LOCAL0 through LOG_LOCAL7.

    If no severity is specified, the default is ERR. If no facility is specified, the default is AUTH. 

In the following example, the logging messages from the KDC will go to the console and to the system log under the facility LOG_DAEMON with default severity of LOG_INFO; and the logging messages from the administrative server will be appended to the file */var/adm/kadmin.log* and sent to the device */dev/tty04*.::

     [logging]
         kdc = CONSOLE
         kdc = SYSLOG:INFO:DAEMON
         admin_server = FILE:/var/adm/kadmin.log
         admin_server = DEVICE=/dev/tty04
     

.. _capaths:

**[capaths]**
~~~~~~~~~~~~~~~~~~~~~~

In order to perform direct (non-hierarchical) cross-realm authentication, a database is needed to construct the authentication paths between the realms. This section defines that database.

A client will use this section to find the authentication path between its realm and the realm of the server. The server will use this section to verify the authentication path used by the client, by checking the transited field of the received ticket.

There is a tag for each participating realm, and each tag has subtags for each of the realms. The value of the subtags is an intermediate realm which may participate in the cross-realm authentication. The subtags may be repeated if there is more then one intermediate realm. A value of "." means that the two realms share keys directly, and no intermediate realms should be allowed to participate.

There are n**2 possible entries in this table, but only those entries which will be needed on the client or the server need to be present. The client needs a tag for its local realm, with subtags for all the realms of servers it will need to authenticate with. A server needs a tag for each realm of the clients it will serve.

For example, *ANL.GOV, PNL.GOV*, and *NERSC.GOV* all wish to use the *ES.NET* realm as an intermediate realm. *ANL* has a sub realm of *TEST.ANL.GOV* which will authenticate with *NERSC.GOV* but not *PNL.GOV*. The [capaths] section for *ANL.GOV* systems would look like this::

     [capaths]
         ANL.GOV = {
             TEST.ANL.GOV = .
             PNL.GOV = ES.NET
             NERSC.GOV = ES.NET
             ES.NET = .
         }
         TEST.ANL.GOV = {
             ANL.GOV = .
         }
         PNL.GOV = {
             ANL.GOV = ES.NET
         }
         NERSC.GOV = {
             ANL.GOV = ES.NET
         }
         ES.NET = {
             ANL.GOV = .
         }
     

The [capaths] section of the configuration file used on *NERSC.GOV* systems would look like this::

     [capaths]
         NERSC.GOV = {
             ANL.GOV = ES.NET
             TEST.ANL.GOV = ES.NET
             TEST.ANL.GOV = ANL.GOV
             PNL.GOV = ES.NET
             ES.NET = .
         }
         ANL.GOV = {
             NERSC.GOV = ES.NET
         }
         PNL.GOV = {
             NERSC.GOV = ES.NET
         }
         ES.NET = {
             NERSC.GOV = .
         }
         TEST.ANL.GOV = {
             NERSC.GOV = ANL.GOV
             NERSC.GOV = ES.NET
         }
     

In the above examples, the ordering is not important, except when the same subtag name is used more then once. The client will use this to determine the path. (It is not important to the server, since the transited field is not sorted.)

This feature is not currently supported by DCE. DCE security servers can be used with Kerberized clients and servers, but versions prior to DCE 1.1 did not fill in the transited field, and should be used with caution.

.. _dbdefaults:

**[dbdefaults]**
~~~~~~~~~~~~~~~~~~~~~~~~

The [dbdefaults] section provides default values for the database specific parameters. It can also specify the configuration section under dbmodules_ section for database specific parameters used by the database library.

The following tags are used in this section:

**database_module**
    This relation indicates the name of the configuration section under the dbmodules_ for database specific parameters used by the loadable database library. 

**ldap_kerberos_container_dn**
    This LDAP specific tag indicates the DN of the container object where the realm objects will be located. This value is used if the container object is not mentioned in the configuration section under dbmodules_. 

**ldap_kdc_dn**
    This LDAP specific tag indicates the default bind DN for the KDC server. The KDC server does a login to the directory as this object. This object should have the rights to read the Kerberos data in the LDAP database. This value is used if the bind DN for the KDC is not mentioned in the configuration section under dbmodules_. 

**ldap_kadmind_dn**
    This LDAP specific tag indicates the default bind DN for the Administration server. The administration server does a login to the directory as this object. This object should have the rights to read and write the Kerberos data in the LDAP database. This value is used if the bind DN for the Administration server is not mentioned in the configuration section under dbmodules_. 

**ldap_service_password_file**
    This LDAP specific tag indicates the file containing the stashed passwords (created by kdb5_ldap_util stashsrvpw) for the objects used by the Kerberos servers to bind to the LDAP server. This file must be kept secure. This value is used if no service password file is mentioned in the configuration section under dbmodules_. 

**ldap_servers**
    This LDAP specific tag indicates the list of LDAP servers that the Kerberos servers can connect to. The list of LDAP servers is whitespace-separated. The LDAP server is specified by a LDAP URI. This value is used if no LDAP servers are mentioned in the configuration section under dbmodules_. It is recommended to use the *ldapi://* or *ldaps://* interface and not to use *ldap://* interface. 

**ldap_conns_per_server**
    This LDAP specific tag indicates the number of connections to be maintained per LDAP server. This value is used if the number of connections per LDAP server are not mentioned in the configuration section under dbmodules_. The default value is 5. 

.. _dbmodules:

**[dbmodules]**
~~~~~~~~~~~~~~~~~~

Contains database specific parameters used by the database library. Each tag in the [dbmodules] section of the file names a configuration section for database specific parameters that can be referred to by a realm. The value of the tag is a subsection where the relations in that subsection define the database specific parameters.

For each section, the following tags may be specified in the subsection:

**database_name**
    This DB2-specific tag indicates the location of the database in the filesystem. The default is */usr/local/var/krb5kdc/principal*. 

**db_library**
    This tag indicates the name of the loadable database library. The value should be *db2* for DB2 database and *kldap* for LDAP database. 

**db_module_dir**
    This tag controls where the plugin system looks for modules. The value should be an absolute path.

**disable_last_success**
    If set to *true*, suppresses KDC updates to the *"Last successful authentication"* field of principal entries requiring preauthentication. Setting this flag may improve performance. (Principal entries which do not require preauthentication never update the "Last successful authentication" field.). 
     
**disable_lockout**
    If set to *true*, suppresses KDC updates to the *"Last failed authentication"* and *"Failed password attempts"* fields of principal entries requiring preauthentication. Setting this flag may improve performance, but also disables account lockout. 

**ldap_conns_per_server**
    This LDAP specific tags indicates the number of connections to be maintained per LDAP server. 

**ldap_kadmind_dn**
    This LDAP specific tag indicates the default bind DN for the Administration server. The administration server does a login to the directory as this object. This object should have the rights to read and write the Kerberos data in the LDAP database. 

**ldap_kdc_dn**
    This LDAP specific tag indicates the default bind DN for the KDC server. The KDC server does a login to the directory as this object. This object should have the rights to read the Kerberos data in the LDAP database. 

**ldap_kerberos_container_dn**
    This LDAP specific tag indicates the DN of the container object where the realm objects will be located. 

**ldap_servers**
    This LDAP specific tag indicates the list of LDAP servers that the Kerberos servers can connect to. The list of LDAP servers is whitespace-separated. The LDAP server is specified by a LDAP URI. It is recommended to use *ldapi://* or *ldaps://* interface to connect to the LDAP server. 

**ldap_service_password_file**
    This LDAP specific tag indicates the file containing the stashed passwords (created by *kdb5_ldap_util stashsrvpw*) for the objects used by the Kerberos servers to bind to the LDAP server. This file must be kept secure. 


.. _appdefaults:

**[appdefaults]**
~~~~~~~~~~~~~~~~~~~~~~~~~

Each tag in the [appdefaults] section names a Kerberos V5 application or an option that is used by some Kerberos V5 application[s]. The value of the tag defines the default behaviors for that application.

For example::

     [appdefaults]
         telnet = {
             ATHENA.MIT.EDU = {
                  option1 = false
             }
         }
         telnet = {
             option1 = true
             option2 = true
         }
         ATHENA.MIT.EDU = {
             option2 = false
         }
         option2 = true
     

The above four ways of specifying the value of an option are shown in order of decreasing precedence. In this example, if telnet is running in the realm EXAMPLE.COM, it should, by default, have option1 and option2 set to true. However, a telnet program in the realm ATHENA.MIT.EDU should have option1 set to false and option2 set to true. Any other programs in ATHENA.MIT.EDU should have option2 set to false by default. Any programs running in other realms should have option2 set to true.

The list of specifiable options for each application may be found in that application's man pages. The application defaults specified here are overridden by those specified in the realms_ section.

.. _plugins:

Plugins
--------

    * pwqual_ interface
    * kadm5_hook_ interface
    * clpreauth_ and kdcpreauth_ interfaces

Tags in the **[plugins]** section can be used to register dynamic plugin modules and to turn modules on and off. Not every krb5 pluggable interface uses the [plugins] section; the ones that do are documented here.

Each pluggable interface corresponds to a subsection of [plugins]. All subsections support the same tags:

**disable**
    This tag may have multiple values. If there are values for this tag, then the named modules will be disabled for the pluggable interface. 

**enable_only**
    This tag may have multiple values. If there are values for this tag, then only the named modules will be enabled for the pluggable interface. 

**module**
    This tag may have multiple values. Each value is a string of the form "modulename:pathname", which causes the shared object located at pathname to be registered as a dynamic module named modulename for the pluggable interface. If pathname is not an absolute path, it will be treated as relative to the "krb5/plugins" subdirectory of the krb5 library directory. 

The following subsections are currently supported within the [plugins] section:

.. _pwqual:

pwqual interface
~~~~~~~~~~~~~~~~~~~~~~~

The **pwqual** subsection controls modules for the password quality interface, which is used to reject weak passwords when passwords are changed. In addition to any registered dynamic modules, the following built-in modules exist (and may be disabled with the disable tag):

**dict**
    Checks against the realm dictionary file 

**empty**
    Rejects empty passwords 

**hesiod**
    Checks against user information stored in Hesiod (only if Kerberos was built with Hesiod support) 

**princ**
    Checks against components of the principal name 

.. _kadm5_hook:

kadm5_hook interface
~~~~~~~~~~~~~~~~~~~~~~~~

The **kadm5_hook** interface provides plugins with information on principal creation, modification, password changes and deletion. This interface can be used to write a plugin to synchronize MIT Kerberos with another database such as Active Directory. No plugins are built in for this interface.

.. _clpreauth:

.. _kdcpreauth:

clpreauth and kdcpreauth interfaces
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The **clpreauth** and **kdcpreauth** interfaces allow plugin modules to provide client and KDC preauthentication mechanisms.  The following built-in modules exist for these interfaces:

**pkinit**
    This module implements the PKINIT preauthentication mechanism.

**encrypted_challenge**
    This module implements the encrypted challenge FAST factor.

**encrypted_timestamp**
    This module implements the encrypted timestamp mechanism.

PKINIT options
-----------------

    * pkinit identity syntax
    * pkinit krb5.conf options

.. note:: The following are pkinit-specific options. Note that these values may be specified in *[libdefaults]* as global defaults, or within a realm-specific subsection of *[libdefaults]*, or may be specified as realm-specific values in the *[realms]* section. Also note that a realm-specific value over-rides, does not add to, a generic *[libdefaults]* specification. The search order is:

   1. realm-specific subsection of [libdefaults]

                [libdefaults]
                    EXAMPLE.COM = {
                        pkinit_anchors = FILE\:/usr/local/example.com.crt

                    }
                

   2. realm-specific value in the [realms] section,

                [realms]
                    OTHERREALM.ORG = {
                        pkinit_anchors = FILE\:/usr/local/otherrealm.org.crt

                    }
                

   3. generic value in the [libdefaults] section.

                [libdefaults]
                    pkinit_anchors = DIR\:/usr/local/generic_trusted_cas/
                


Specifying pkinit identity information
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The syntax for specifying Public Key identity, trust, and revocation information for pkinit is as follows:


FILE\:file-name\[,key-file-name]
    This option has context-specific behavior.

    | pkinit_identity
    | pkinit_identities

        *file-name* specifies the name of a PEM-format file containing the user's certificate. If *key-file-name* is not specified, the user's private key is expected to be in file-name as well. Otherwise, *key-file-name* is the name of the file containing the private key.

    | pkinit_anchors
    | pkinit_pool

        *file-name* is assumed to be the name of an OpenSSL-style ca-bundle file. 


DIR:directory-name
    This option has context-specific behavior.

    | pkinit_identity
    | pkinit_identities

        *directory-name* specifies a directory with files named \*.crt and \*.key, where the first part of the file name is the same for matching pairs of certificate and private key files. When a file with a name ending with .crt is found, a matching file ending with .key is assumed to contain the private key. If no such file is found, then the certificate in the .crt is not used.

    | pkinit_anchors
    | pkinit_pool

        *directory-name* is assumed to be an OpenSSL-style hashed CA directory where each CA cert is stored in a file named *hash-of-ca-cert.#*. This infrastructure is encouraged, but all files in the directory will be examined and if they contain certificates (in PEM format), they will be used.

    pkinit_revoke
        *directory-name* is assumed to be an OpenSSL-style hashed CA directory where each revocation list is stored in a file named *hash-of-ca-cert.r#*. This infrastructure is encouraged, but all files in the directory will be examined and if they contain a revocation list (in PEM format), they will be used. 


PKCS12:pkcs12-file-name
    *pkcs12-file-name* is the name of a PKCS #12 format file, containing the user's certificate and private key.
PKCS11:[module_name=]module-name[:slotid=slot-id][:token=token-label][:certid=cert-id][:certlabel=cert-label]
    All keyword/values are optional. module-name specifies the location of a library implementing PKCS #11. If a value is encountered with no keyword, it is assumed to be the *module-name*. If no module-name is specified, the default is *opensc-pkcs11.so*. *slotid=* and/or *token=* may be specified to force the use of a particular smard card reader or token if there is more than one available. *certid=* and/or *certlabel=* may be specified to force the selection of a particular certificate on the device. See the *pkinit_cert_match* configuration option for more ways to select a particular certificate to use for pkinit.
ENV:environment-variable-name
    environment-variable-name specifies the name of an environment variable which has been set to a value conforming to one of the previous values. For example, *ENV:X509_PROXY*, where environment variable *X509_PROXY* has been set to *FILE:/tmp/my_proxy.pem*. 



PKINIT krb5.conf options
~~~~~~~~~~~~~~~~~~~~~~~~


**pkinit_anchors**
    Specifies the location of trusted anchor (root) certificates which the client trusts to sign KDC certificates. This option may be specified multiple times. These values from the config file are not used if the user specifies X509_anchors on the command line.

**pkinit_cert_match**
    Specifies matching rules that the client certificate must match before it is used to attempt pkinit authentication. If a user has multiple certificates available (on a smart card, or via other media), there must be exactly one certificate chosen before attempting pkinit authentication. This option may be specified multiple times. All the available certificates are checked against each rule in order until there is a match of exactly one certificate.

    The Subject and Issuer comparison strings are the :rfc:`2253` string representations from the certificate Subject DN and Issuer DN values.

    The syntax of the matching rules is::

              [relation-operator]component-rule ...
              

    where

    *relation-operator*
        can be either **&&**, meaning all component rules must match, or **||**, meaning only one component rule must match. The default is &&.
    *component-rule*
        can be one of the following. Note that there is no punctuation or whitespace between component rules.

        *<SUBJECT>regular-expression*

        *<ISSUER>regular-expression*

        *<SAN>regular-expression*

        *<EKU>extended-key-usage-list*
            where *extended-key-usage-list* is a comma-separated list of required Extended Key Usage values. All values in the list must be present in the certificate.

                              -  pkinit
                              -  msScLogin
                              -  clientAuth
                              -  emailProtection
                                


        *<KU>key-usage-list*
            where *key-usage-list* is a comma-separated list of required Key Usage values. All values in the list must be present in the certificate.

                              - digitalSignature
                              - keyEncipherment
                                

    Examples::

              pkinit_cert_match = ||<SUBJECT>.*DoE.*<SAN>.*@EXAMPLE.COM
              pkinit_cert_match = &&<EKU>msScLogin,clientAuth<ISSUER>.*DoE.*
              pkinit_cert_match = <EKU>msScLogin,clientAuth<KU>digitalSignature
              
**pkinit_eku_checking**
    This option specifies what Extended Key Usage value the KDC certificate presented to the client must contain. (Note that if the KDC certificate has the pkinit SubjectAlternativeName encoded as the Kerberos TGS name, EKU checking is not necessary since the issuing CA has certified this as a KDC certificate.) The values recognized in the krb5.conf file are:

    *kpKDC*
        This is the default value and specifies that the KDC must have the id-pkinit-KPKdc EKU as defined in :rfc:`4556`.
    *kpServerAuth*
        If kpServerAuth is specified, a KDC certificate with the id-kp-serverAuth EKU as used by Microsoft will be accepted.
    *none*
        If none is specified, then the KDC certificate will not be checked to verify it has an acceptable EKU. The use of this option is not recommended. 

**pkinit_dh_min_bits**
    Specifies the size of the Diffie-Hellman key the client will attempt to use. The acceptable values are currently 1024, 2048, and 4096. The default is 2048.

**pkinit_identities**
    Specifies the location(s) to be used to find the user's X.509 identity information. This option may be specified multiple times. Each value is attempted in order until identity information is found and authentication is attempted. Note that these values are not used if the user specifies X509_user_identity on the command line.

**pkinit_kdc_hostname**
    The presense of this option indicates that the client is willing to accept a KDC certificate with a dNSName SAN (Subject Alternative Name) rather than requiring the id-pkinit-san as defined in :rfc:`4556`. This option may be specified multiple times. Its value should contain the acceptable hostname for the KDC (as contained in its certificate).

**pkinit_longhorn**
    If this flag is set to true, we are talking to the Longhorn KDC.

**pkinit_pool**
    Specifies the location of intermediate certificates which may be used by the client to complete the trust chain between a KDC certificate and a trusted anchor. This option may be specified multiple times.

**pkinit_require_crl_checking**
    The default certificate verification process will always check the available revocation information to see if a certificate has been revoked. If a match is found for the certificate in a CRL, verification fails. If the certificate being verified is not listed in a CRL, or there is no CRL present for its issuing CA, and *pkinit_require_crl_checking* is false, then verification succeeds.

    However, if *pkinit_require_crl_checking* is true and there is no CRL information available for the issuing CA, then verification fails.

    *pkinit_require_crl_checking* should be set to true if the policy is such that up-to-date CRLs must be present for every CA.

**pkinit_revoke**
    Specifies the location of Certificate Revocation List (CRL) information to be used by the client when verifying the validity of the KDC certificate presented. This option may be specified multiple times.

**pkinit_win2k**
    This flag specifies whether the target realm is assumed to support only the old, pre-RFC version of the protocol. The default is false.

**pkinit_win2k_require_binding**
    If this flag is set to true, it expects that the target KDC is patched to return a reply with a checksum rather than a nonce. The default is false.



.. _krb5_conf_sample_label:

Sample krb5.conf file
-------------------------

Here is an example of a generic krb5.conf file::

     [libdefaults]
         default_realm = ATHENA.MIT.EDU
         default_tkt_enctypes = des3-hmac-sha1 des-cbc-crc
         default_tgs_enctypes = des3-hmac-sha1 des-cbc-crc
         dns_lookup_kdc = true
         dns_lookup_realm = false
     
     [realms]
         ATHENA.MIT.EDU = {
             kdc = kerberos.mit.edu
             kdc = kerberos-1.mit.edu
             kdc = kerberos-2.mit.edu:750
             admin_server = kerberos.mit.edu
             master_kdc = kerberos.mit.edu
             default_domain = mit.edu
         }
         EXAMPLE.COM = {
             kdc = kerberos.example.com
             kdc = kerberos-1.example.com
             admin_server = kerberos.example.com
         }
         OPENLDAP.MIT.EDU = {
             kdc = kerberos.mit.edu
             admin_server = kerberos.mit.edu
             database_module = openldap_ldapconf
         }
     
     [domain_realm]
         .mit.edu = ATHENA.MIT.EDU
         mit.edu = ATHENA.MIT.EDU
     
     [capaths]
         ATHENA.MIT.EDU = {
         	EXAMPLE.COM = .
         }
         EXAMPLE.COM = {
         	ATHENA.MIT.EDU = .
         }
     
     [logging]
         kdc = SYSLOG:INFO
         admin_server = FILE=/var/kadm5.log
     [dbdefaults]
         ldap_kerberos_container_dn = cn=krbcontainer,dc=example,dc=com
     [dbmodules]
         openldap_ldapconf = {
             db_library = kldap
             disable_last_success = true
             ldap_kerberos_container_dn = cn=krbcontainer,dc=example,dc=com
             ldap_kdc_dn = "cn=krbadmin,dc=example,dc=com"
                 # this object needs to have read rights on
                 # the realm container and principal subtrees
             ldap_kadmind_dn = "cn=krbadmin,dc=example,dc=com"
                 # this object needs to have read and write rights on
                 # the realm container and principal subtrees
             ldap_service_password_file = /etc/kerberos/service.keyfile
             ldap_servers = ldaps://kerberos.mit.edu
             ldap_conns_per_server = 5
     }
     
FILES
--------

/etc/krb5.conf

SEE ALSO
-----------

syslog(3)




