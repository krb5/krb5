.. _create_stash:

Creating a stash file
============================

A stash file allows a KDC to authenticate itself to the database utilities, such as *kadmin, kadmind, krb5kdc*, and *kdb5_util*.

To create a stash file, use the :ref:`kdb5_util(8)`  *stash* command.

.. include:: ../../admin_commands/kdb5_util.rst
   :start-after: _kdb5_util_stash: 
   :end-before: _kdb5_util_stash_end:



EXAMPLE::

     shell% kdb5_util stash
     kdb5_util: Cannot find/read stored master key while reading master key
     kdb5_util: Warning: proceeding without master key
     Enter KDC database master key:  <= Type the KDC database master password.
     shell%
     

If you do not specify a stash file, *kdb5_util* will stash the key in the file specified in your :ref:`kdc.conf` file. 


     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_operations

