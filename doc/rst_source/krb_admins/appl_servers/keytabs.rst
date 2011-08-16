Keytabs
==============

A keytab is a host's copy of its own keylist, which is analogous to a user's password. An application server that needs to authenticate itself to the KDC has to have a keytab that contains its own principal and key. Just as it is important for users to protect their passwords, it is equally important for hosts to protect their keytabs. You should always store keytab files on local disk, and make them readable only by root, and you should never send a keytab file over a network in the clear. Ideally, you should run the kadmin command to extract a keytab on the host on which the keytab is to reside. 


.. _add_princ_kt:

Adding Principals to Keytabs
----------------------------------

To generate a keytab, or to add a principal to an existing keytab, use the **ktadd** command from kadmin, which requires the "inquire" administrative privilege. (If you use the -glob princ_exp option, it also requires the "list" administrative privilege.) The syntax is::

     ktadd [-k[eytab] keytab] [-q] [-e key:salt_list] [principal | -glob princ_exp] [...]
     

The *ktadd* command takes the following switches

============================================= =================================================================
-k[eytab] *keytab*                                Use keytab as the keytab file. Otherwise, *ktadd* will use the default keytab file (*/etc/krb5.keytab*).
-e *"enc:salt..."*                                Uses the specified list of enctype-salttype pairs for setting the key of the principal. The quotes are necessary if there are multiple enctype-salttype pairs. This will not function against kadmin daemons earlier than krb5-1.2. See :ref:`Supported_Encryption_Types_and_Salts` for all possible values.
-q                                                Run in quiet mode. This causes *ktadd* to display less verbose information.
principal | -glob *principal expression*          Add principal, or all principals matching principal expression to the keytab. The rules for principal expression are the same as for the kadmin list_principals (see :ref:`get_list_princs`) command. 
============================================= =================================================================

Here is a sample session, using configuration files that enable only *des-cbc-crc* encryption. (The line beginning with => is a continuation of the previous line.)::

     kadmin: ktadd host/daffodil.mit.edu@ATHENA.MIT.EDU
     kadmin: Entry for principal host/daffodil.mit.edu@ATHENA.MIT.EDU with
          kvno 2, encryption type DES-CBC-CRC added to keytab
          WRFILE:/etc/krb5.keytab.
     kadmin:
     

     kadmin: ktadd -k /usr/local/var/krb5kdc/kadmind.keytab
     => kadmin/admin kadmin/changepw
     kadmin: Entry for principal kadmin/admin@ATHENA.MIT.EDU with
          kvno 3, encryption type DES-CBC-CRC added to keytab
          WRFILE:/usr/local/var/krb5kdc/kadmind.keytab.
     kadmin:
     

Removing Principals from Keytabs
---------------------------------

To remove a principal from an existing keytab, use the kadmin **ktremove** command. The syntax is::

     ktremove [-k[eytab] keytab] [-q] principal [kvno | all | old]
     

The *ktremove* command takes the following switches


====================== ====================================
-k[eytab] *keytab*      Use keytab as the keytab file. Otherwise, *ktremove* will use the default keytab file (*/etc/krb5.keytab*).
-q                      Run in quiet mode. This causes *ktremove* to display less verbose information.
*principal*             The principal to remove from the keytab. (Required.)
*kvno*                       Remove all entries for the specified principal whose Key Version Numbers match *kvno*.
all                        Remove all entries for the specified principal
old                      Remove all entries for the specified principal *except those with the highest kvno*. 
====================== ====================================

For example::

     kadmin: ktremove -k /usr/local/var/krb5kdc/kadmind.keytab kadmin/admin
     kadmin: Entry for principal kadmin/admin with kvno 3 removed
          from keytab WRFILE:/usr/local/var/krb5kdc/kadmind.keytab.
     kadmin:
     
----------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___appl_servers

