Dumping a Kerberos database to a file
=============================================

To dump a Kerberos database into a file, use the *kdb5_util dump* command on one of the KDCs. The syntax is:

     kdb5_util dump [-old] [-b6] [-b7] [-ov]
     [-verbose] [-mkey_convert] [-new_mkey_file] [filename
     [principals...]]
     

The kdb5_util dump command takes the following options

================= ============================================================
-old               Causes the dump to be in the Kerberos 5 Beta 5 and earlier dump format ("kdb5_edit load_dump version 2.0"). 
-b6                Causes the dump to be in the Kerberos 5 Beta 6 format ("kdb5_edit load_dump version 3.0"). 
-b7                Causes the dump to be in the Kerberos 5 Beta 7 format ("kdbt_edit load_dump version 4"). 
-ov                Causes the dump to be in ovsec_adm_export format. Currently, the only way to preserve per-principal policy information is to use this in conjunction with a normal dump. 
-verbose           Causes the name of each principal and policy to be printed as it is dumped. 
-mkey_convert      Prompts for a new master password, and then dumps the database with all keys reencrypted in this new master key 
-new_mkey_file    Reads a new key from the default keytab and then dumps the database with all keys reencrypted in this new master key 
================= ============================================================

For example::

     shell% kdb5_util dump dumpfile
     shell%
     

     shell% kbd5_util dump -verbose dumpfile
     kadmin/admin@ATHENA.MIT.EDU
     krbtgt/ATHENA.MIT.EDU@ATHENA.MIT.EDU
     kadmin/history@ATHENA.MIT.EDU
     K/M@ATHENA.MIT.EDU
     kadmin/changepw@ATHENA.MIT.EDU
     shell%
     

If you specify which principals to dump, you must use the full principal, as in the following example. (The line beginning with => is a continuation of the previous line.)::

     shell% kdb5_util dump -verbose dumpfile K/M@ATHENA.MIT.EDU
     => kadmin/admin@ATHENA.MIT.EDU
     kadmin/admin@ATHENA.MIT.EDU
     K/M@ATHENA.MIT.EDU
     shell%
     

Otherwise, the principals will not match those in the database and will not be dumped::

     shell% kdb5_util dump -verbose dumpfile K/M kadmin/admin
     shell%
     

If you do not specify a dump file, *kdb5_util* will dump the database to the standard output.

There is currently a bug where the default dump format omits the per-principal policy information. In order to dump all the data contained in the Kerberos database, you must perform a normal dump (with no option flags) and an additional dump using the "-ov" flag to a different file. 


     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_operations

