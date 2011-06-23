.. _create_stash:

Creating a Stash File
============================

A stash file allows a KDC to authenticate itself to the database utilities, such as *kadmin, kadmind, krb5kdc*, and *kdb5_util*.

To create a stash file, use the *kdb5_util stash* command. The syntax is::

     kdb5_util stash [-f keyfile]
     

For example::

     shell% kdb5_util stash
     kdb5_util: Cannot find/read stored master key while reading master key
     kdb5_util: Warning: proceeding without master key
     Enter KDC database master key:  <= Type the KDC database master password.
     shell%
     

If you do not specify a stash file, *kdb5_util* will stash the key in the file specified in your *kdc.conf* file. 


     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_operations

