Keytabs
==============

A keytab is a host's copy of its own keylist, which is analogous to a user's password. An application server that needs to authenticate itself to the KDC has to have a keytab that contains its own principal and key. Just as it is important for users to protect their passwords, it is equally important for hosts to protect their keytabs. You should always store keytab files on local disk, and make them readable only by root, and you should never send a keytab file over a network in the clear. Ideally, you should run the *kadmin* command to extract a keytab on the host on which the keytab is to reside. 


.. _add_princ_kt:

Adding principals to keytabs
----------------------------------


To generate a keytab, or to add a principal to an existing keytab, use the **ktadd** command from *kadmin*.

.. include:: ../admin_commands/kadmin_local.rst
   :start-after:  _ktadd:
   :end-before: _ktadd_end:


.. note::  Alternatively, the keytab can be generated using :ref:`ktutil(1)`  *add_entry -password* and  *write_kt* commands.



EXAMPLES:

     Here is a sample session, using configuration files that enable only *des-cbc-crc* encryption::

        kadmin: ktadd host/daffodil.mit.edu@ATHENA.MIT.EDU
        kadmin: Entry for principal host/daffodil.mit.edu@ATHENA.MIT.EDU with kvno 2, encryption type DES-CBC-CRC added to keytab WRFILE:/etc/krb5.keytab.
        kadmin:
     

        kadmin: ktadd -k /usr/local/var/krb5kdc/kadmind.keytab kadmin/admin kadmin/changepw
        kadmin: Entry for principal kadmin/admin@ATHENA.MIT.EDU with kvno 3, encryption type DES-CBC-CRC added to keytab WRFILE:/usr/local/var/krb5kdc/kadmind.keytab.
        kadmin:
     

Removing principals from keytabs
---------------------------------

To remove a principal from an existing keytab, use the *kadmin* **ktremove** command. 

.. include:: ../admin_commands/kadmin_local.rst
   :start-after:  _ktremove:
   :end-before: _ktremove_end:


Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___appl_servers

