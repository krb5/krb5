Edit the configuration files
==================================

Modify the configuration files, */etc/krb5.conf* and */usr/local/var/krb5kdc/kdc.conf* to reflect the correct information (such as the hostnames and realm name) for your realm. MIT recommends that you keep *krb5.conf* in */etc*.

Most of the tags in the configuration have default values that will work well for most sites. There are some tags in the *krb5.conf* file whose values must be specified, and this section will explain those. For more information on Kerberos V5 configuration files see :ref:`krb5.conf` and :ref:`kdc.conf`.

*krb5.conf*
-------------

If you are not using DNS TXT records (see :ref:`mapping_hn_label`), you must specify the *default_realm* in the :ref:`libdefaults` section. If you are not using DNS SRV records (see :ref:`kdc_hn_label`), you must include the *kdc* tag for each *realm* in the :ref:`realms` section. To communicate with the kadmin server in each realm, the *admin_server* tag must be set in the :ref:`realms` section. If your domain name and realm name are not the same, you must provide a translation in *domain_realm*. It is also higly recommeneded that you create a :ref:`logging` stanza if the computer will be functioning as a KDC so that the KDC and kadmind will generate logging output.

An example krb5.conf file::

     [libdefaults]
         default_realm = ATHENA.MIT.EDU
     
     [realms]
         ATHENA.MIT.EDU = {
         	kdc = kerberos.mit.edu
         	kdc = kerberos-1.mit.edu
         	kdc = kerberos-2.mit.edu
         	admin_server = kerberos.mit.edu
         {
     
     [logging]
         kdc = FILE:/var/log/krb5kdc.log
         admin_server = FILE:/var/log/kadmin.log
         default = FILE:/var/log/krb5lib.log
     
------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc

