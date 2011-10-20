osconf.hin
==============

There is one configuration file which you may wish to edit to control various compile-time parameters in the Kerberos distribution::

   include/stock/osconf.hin

The list that follows is by no means complete, just some of the more interesting variables.

.. note::  The former configuration file config.h no longer exists 
           as its functionality has been merged into the auto-configuration process. See Options to Configure.


**DEFAULT_PROFILE_PATH**
    The pathname to the file which contains the profiles for the known realms, their KDCs, etc. The default value is /etc/krb5.conf.

    The profile file format is no longer the same format as Kerberos V4's krb.conf file.
**DEFAULT_KEYTAB_NAME**
    The type and pathname to the default server keytab file (the equivalent of Kerberos V4's /etc/srvtab). The default is /etc/krb5.keytab.
**DEFAULT_KDC_ENCTYPE**
    The default encryption type for the KDC. The default value is des3-cbc-sha1.
**KDCRCACHE**
    The name of the replay cache used by the KDC. The default value is krb5kdc_rcache.
**RCTMPDIR**
    The directory which stores replay caches. The default is to try /var/tmp, /usr/tmp, /var/usr/tmp, and /tmp.
**DEFAULT_KDB_FILE**
    The location of the default database. The default value is /usr/local/var/krb5kdc/principal. 
