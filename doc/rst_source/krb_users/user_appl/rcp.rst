rcp
=============

The Kerberos V5 *rcp* program works exactly like the standard UNIX *rcp* program, with the following Kerberos features added:

============= ================
-k *realm*    requests tickets for the remote host in the specified realm, instead of determining the realm itself.
-x            turns on encryption.
============= ================

For example, if you wanted to copy the file */etc/motd* from the host *daffodil.mit.edu* into the current directory, via an encrypted connection, you would simply type::

     shell% rcp -x daffodil.mit.edu:/etc/motd .

The *rcp* program negotiates authentication and encryption transparently. 

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_appl


