Edit the configuration files
==================================

Modify the configuration files, *krb5.conf* and *kdc.conf* to reflect the correct information
(such as domain-realm mappings and Kerberos servers names) for your realm. 
(See :ref:`mitK5defaults` for the recommended default locations for these files). 

Most of the tags in the configuration have default values that will work well for most sites. 
There are some tags in the *krb5.conf* file whose values must be specified, 
and this section will explain those. 
For more information on Kerberos V5 configuration files see :ref:`krb5.conf` and :ref:`kdc.conf`.

If the locations for these configuration files differs from the default ones,
set *KRB5_CONFIG* and *KRB5_KDC_PROFILE* environment variables to point to the 
*krb5.conf* and *kdc.conf* respectively.
For example::

   export KRB5_CONFIG=/yourdir/krb5.conf
   export KRB5_KDC_PROFILE=/yourdir/kdc.conf

*krb5.conf*
-------------

If you are not using DNS TXT records (see :ref:`mapping_hn_label`), you must specify the *default_realm* in the :ref:`libdefaults` section.
If you are not using DNS SRV records (see :ref:`kdc_hn_label`), you must include the *kdc* tag for each *realm* in the :ref:`realms` section.
To communicate with the kadmin server in each realm, the *admin_server* tag must be set in the :ref:`realms` section.
If your domain name and realm name are not the same, you must provide a translation in :ref:`domain_realm`.
It is also higly recommeneded that you create a :ref:`logging` stanza if the computer will be functioning as a KDC 
so that the KDC and *kadmind* will generate logging output.


An example krb5.conf file::


     [libdefaults]
         default_realm = ATHENA.MIT.EDU
         # if the default location does not suit your setup,
         # explicitly configure the keytab location:
         #    default_keytab_name = FILE:/var/krb5kdc/krb5.keytab
     
     [realms]
         ATHENA.MIT.EDU = {
         	kdc = kerberos.mit.edu
         	kdc = kerberos-1.mit.edu
         	kdc = kerberos-2.mit.edu
         	admin_server = kerberos.mit.edu
         }

     [logging]
         kdc = FILE:/var/log/krb5kdc.log
         admin_server = FILE:/var/log/kadmin.log
         default = FILE:/var/log/krb5lib.log
     

An example kdc.conf file::

     [kdcdefaults]
         kdc_ports = 88,750
     
     [realms]
         ATHENA.MIT.EDU = {
             kadmind_port = 749
             max_life = 12h 0m 0s
             max_renewable_life = 7d 0h 0m 0s
             master_key_type = des3-hmac-sha1
             supported_enctypes = des3-hmac-sha1:normal aes128-cts-hmac-sha1-96:normal
             # if the default location does not suit your setup,
             # explicitly configure the following four values:
             #    database_name = /var/krb5kdc/principal             
             #    key_stash_file = /var/krb5kdc/.k5.ATHENA.MIT.EDU
             #    admin_keytab = FILE:/var/krb5kdc/kadm5.keytab
             #    acl_file = /var/krb5kdc/kadm5.acl
         }
     

Replace *ATHENA.MIT.EDU* and *kerberos.mit.edu*  with the name of your Kerberos *realm* and *server* respectively.

.. note:: You have to have write permission on the target directories 
          (these directories must exist) used by
          *database_name, key_stash_file, admin_keytab* and *acl_file*



------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc

