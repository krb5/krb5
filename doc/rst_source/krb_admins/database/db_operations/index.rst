.. _db_operations_label:

Operations on the Kerberos database
=============================================

The *kdb5_util command* is the primary tool for administrating the Kerberos database. The syntax is::

     kdb5_util command [kdb5_util_options] [command_options]
     

The *kdb5_util command* takes the following options, which **override the defaults** specified in the configuration files:

========================== =============================================================
-r *realm*                     Specifies the the Kerberos realm of the database. 
-d *database_name*             Specifies the name under which the principal database is stored. 
-k *master_key_type*           Specifies the key type of the master key in the database. 
-M *master_key_name*          Specifies the principal name of the master key in the database. 
-m                           Indicates that the master database password should be read from the TTY rather than fetched from a file on disk. 
-sf *stash_file*              Specifies the stash file of the master database password 
-P *password*                  Specifies the master database password. MIT does not recommend using this option. 
========================== =============================================================

|

.. toctree::
   :maxdepth: 1


   db2file.rst
   file2db.rst
   create_stash.rst
   create_destroy_db.rst


     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_operations

