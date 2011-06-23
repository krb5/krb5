.. _restore_from_dump:


Restoring a Kerberos database from a dump file
================================================

To restore a Kerberos database dump from a file, use the *kdb5_util load* command on one of the KDCs. The syntax is::

     kdb5_util load [-old] [-b6] [-b7] [-ov] [-verbose]
     [-update] [-hash] dumpfilename dbname [admin_dbname]
     

The kdb5_util load command takes the following options

==================== ===========================================================
-old                   Requires the dump to be in the Kerberos 5 Beta 5 and earlier dump format ("kdb5_edit load_dump version 2.0"). 
-b6                    Requires the dump to be in the Kerberos 5 Beta 6 format ("kdb5_edit load_dump version 3.0"). 
-b7                    Requires the dump to be in the Kerberos 5 Beta 7 format ("kdb5_edit load_dump version 4"). 
-ov                    Requires the dump to be in ovsec_adm_export format. 
-verbose               Causes the name of each principal and policy to be printed as it is loaded. 
-update                 Causes records from the dump file to be updated in or added to the existing database. This is useful in conjunction with an ovsec_adm_export format dump if you want to preserve per-principal policy information, since the current default format does not contain this data. 
-hash                  Causes the database to be stored as a hash rather than a binary tree. 
==================== ===========================================================

For example::

     shell% kdb5_util load dumpfile principal
     shell%
     

     shell% kdb5_util load -update dumpfile principal
     shell%
     

If the database file exists, and the *-update* flag was not given, kdb5_util will overwrite the existing database. 

     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_operations

