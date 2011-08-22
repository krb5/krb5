Dumping a Kerberos database to a file
=============================================

To dump a Kerberos database into a file, use the :ref:`kdb5_util(8)` **dump** command on one of the KDCs. 


.. include:: ../../admin_commands/kdb5_util.rst
   :start-after:  _kdb5_util_dump:
   :end-before: _kdb5_util_dump_end:



     
EXAMPLES::

     shell% kdb5_util dump dumpfile
     shell%

     shell% kbd5_util dump -verbose dumpfile
     kadmin/admin@ATHENA.MIT.EDU
     krbtgt/ATHENA.MIT.EDU@ATHENA.MIT.EDU
     kadmin/history@ATHENA.MIT.EDU
     K/M@ATHENA.MIT.EDU
     kadmin/changepw@ATHENA.MIT.EDU
     shell%
     

If you specify which principals to dump, you must use the full principal, as in the following example::

     shell% kdb5_util dump -verbose dumpfile K/M@ATHENA.MIT.EDU kadmin/admin@ATHENA.MIT.EDU
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

