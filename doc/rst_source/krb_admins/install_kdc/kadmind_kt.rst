Create a kadmind keytab 
=================================

.. note:: This operation is optional.


The *kadmind keytab* is the key that the legacy admininstration daemons *kadmind4* and *v5passwdd* will use to decrypt administrators' or clients' Kerberos tickets to determine whether or not they should have access to the database. You need to create the kadmin keytab with entries for the principals *kadmin/admin* and *kadmin/changepw*. (These principals are placed in the Kerberos database automatically when you create it.) To create the kadmin keytab, run *kadmin.local* and use the :ref:`ktadd` command, as in the following example::

     shell% /usr/local/sbin/kadmin.local
     kadmin.local: ktadd -k /usr/local/var/krb5kdc/kadm5.keytab kadmin/admin kadmin/changepw
      Entry for principal kadmin/admin with kvno 5, encryption
     	type Triple DES cbc mode with HMAC/sha1 added to keytab
     	WRFILE:/usr/local/var/krb5kdc/kadm5.keytab.
     Entry for principal kadmin/admin with kvno 5, encryption type DES cbc mode
     	with CRC-32 added to keytab
     	WRFILE:/usr/local/var/krb5kdc/kadm5.keytab.
     Entry for principal kadmin/changepw with kvno 5, encryption
     	type Triple DES cbc mode with HMAC/sha1 added to keytab
     	WRFILE:/usr/local/var/krb5kdc/kadm5.keytab.
     Entry for principal kadmin/changepw with kvno 5,
     	encryption type DES cbc mode with CRC-32 added to keytab
     	WRFILE:/usr/local/var/krb5kdc/kadm5.keytab.
     kadmin.local: quit
     shell%
     

As specified in the *-k* argument, :ref:`ktadd` will save the extracted keytab as */usr/local/var/krb5kdc/kadm5.keytab* (This is also the default location for the admin keytab). The filename you use must be the one specified in your *kdc.conf* file. 


------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc


