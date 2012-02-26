.. _mitK5defaults:

MIT Kerberos defaults
=====================

The list of the site- and OS- dependent configuration
-----------------------------------------------------

 ================================================== ============================================== =====================================
            \                                          Default                                                   Environment
 ================================================== ============================================== =====================================
 Keytab file                                        FILE\:/etc/krb5.keytab                           KRB5_KTNAME
 Path to Kerberos configuration file                /etc/krb5.conf:SYSCONFDIR/krb5.conf              KRB5_CONFIG
 KDC configuration file                             LOCALSTATEDIR/krb5kdc/kdc.conf                   KRB5_KDC_PROFILE
 The location of the default database               LOCALSTATEDIR/krb5kdc/principal
 Master key stash file location and prefix          LOCALSTATEDIR/krb5kdc/.k5.
                                                    (e.g., /usr/local/var/krb5kdc/.k5.YOURREALM)
 Admin Access Control List (ACL) file               LOCALSTATEDIR/krb5kdc/krb5_adm.acl
 Admin ACL file used by old admin server            LOCALSTATEDIR/krb5kdc/kadm_old.acl
 Kerberos database library path                     MODULEDIR/kdb
 Base directory where plugins are located           LIBDIR/krb5/plugins
 Master key default enctype                         ENCTYPE_AES256_CTS_HMAC_SHA1_96
 The name of the replay cache used by KDC           dfl:krb5kdc_rcache                              KRB5RCACHETYPE, KRB5RCACHENAME
 KDC portname used for /etc/services or equiv.      "kerberos"
 KDC secondary portname for backward compatibility  "kerberos-sec"
 KDC default port                                   88
 KDC default port for authentication                750
 Admin change password port                         464
 KDC UDP default portlist                           "88,750"
 ================================================== ============================================== =====================================


MAC OS specific
---------------

 ============================================================ ================================
 Path to Kerberos config file                                   ~/Library/Preferences/edu.mit.Kerberos:/etc/krb5.conf:SYSCONFDIR/krb5.conf
 Base directory where krb5 plugins are located                  /System/Library/KerberosPlugins/KerberosFrameworkPlugins
 Base directory where Kerberos databadse plugins are located    /System/Library/KerberosPlugins/KerberosDatabasePlugins
 Base directory where authorization data plugins are located    /System/Library/KerberosPlugins/KerberosAuthDataPlugins
 ============================================================ ================================


Windows specific
----------------

 ======================================= ====================================================
 Kerberos config file name                krb5.ini
 Keytab file name                         FILE\:%s\\krb5kt (for example, C:\\WINDOWS\\krb5kt)
 ======================================= ====================================================


Defaults for the KADM5 admin system
-----------------------------------

 ====================================================================== ====================================== ==============================
  \                                                                          Default                               Environment
 ====================================================================== ====================================== ==============================
 Admin keytab file                                                       LOCALSTATEDIR/krb5kdc/kadm5.keytab      KRB5_KTNAME
 Admin ACL file that defines access rights to the Kerberos database      LOCALSTATEDIR/krb5kdc/kadm5.acl
 Admin server default port                                               749
 Default supported enctype/salttype matrix                               aes256-cts-hmac-sha1-96:normal
                                                                         aes128-cts-hmac-sha1-96:normal
                                                                         des3-cbc-sha1:normal
                                                                         arcfour-hmac-md5:normal
 Max datagram size                                                       4096
 Directory to store replay caches                                        KRB5RCTMPDIR                            KRB5RCACHEDIR
 Kerberized login program                                                SBINDIR/login.krb5
 Kerberized remote login program                                         BINDIR/rlogin
 ====================================================================== ====================================== ==============================


krb5 *slave* support
--------------------

 ============================================================ ======================================= ===============================
  \                                                                          Default                               Environment
 ============================================================ ======================================= ===============================
 kprop  database dump file                                     LOCALSTATEDIR/krb5kdc/slave_datatrans
 kpropd temporary database file                                LOCALSTATEDIR/krb5kdc/from_master
 Location of the utility used to load the principal database   SBINDIR/kdb5_util
 kpropd default kprop                                          SBINDIR/kprop
 kpropd principal database location                            LOCALSTATEDIR/krb5kdc/principal
 kpropd ACL file                                               LOCALSTATEDIR/krb5kdc/kpropd.acl
 kprop port                                                    754                                       KPROP_PORT
 ============================================================ ======================================= ===============================


Site- and system-wide initialization for the code compiled on Linux or Solaris
------------------------------------------------------------------------------

 ===================== ============================== =================
 BINDIR                /usr/local/bin/
 KRB5RCTMPDIR          /var/tmp
 LIBDIR                /usr/local/lib/                 krb5 library directory
 LOCALSTATEDIR         /usr/local/var/
 MODULEDIR             /usr/local/lib/krb5/plugins/    krb5 static plugins directory
 SBINDIR               /usr/local/sbin/
 SYSCONFDIR            /usr/local/etc/
 ===================== ============================== =================


Report the problem
------------------

Please, provide your feedback on this document at
krb5-bugsmit.edu?subject=Documentation___krb5_implementation_features
