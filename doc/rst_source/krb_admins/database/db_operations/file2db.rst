.. _restore_from_dump:


Restoring a Kerberos database from a dump file
================================================

To restore a Kerberos database dump from a file, use the :ref:`kdb5_util(8)` **load** command on one of the KDCs.

.. include:: ../../admin_commands/kdb5_util.rst
   :start-after:  _kdb5_util_load:
   :end-before: _kdb5_util_load_end:


EXAMPLES::

     shell% kdb5_util load dumpfile principal
     shell%
     

     shell% kdb5_util load -update dumpfile principal
     shell%
     

.. note:: If the database file exists, and the *-update* flag was not given, *kdb5_util* will overwrite the existing database. 

     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_operations

