rsh
================
The Kerberos V5 rsh program works exactly like the standard UNIX rlogin program, with the following Kerberos features added:

========== ======================
-f         forwards a copy of your tickets to the remote host.
-F         forwards a copy of your tickets to the remote host, and marks them re-forwardable from the remote host.
-k *realm*   requests tickets for the remote host in the specified realm, instead of determining the realm itself.
-x         encrypts the input and output data streams (the command line is not encrypted)
========== ======================

For example, if your Kerberos tickets allowed you to run programs on the host *trillium@example.com* as root, you could run the date program as follows::

     shell% rsh trillium.example.com -l root -x date
     This rsh session is using DES encryption for all data transmissions.
     Tue Jul 30 19:34:21 EDT 2002
     shell%

If you forwarded your Kerberos tickets, *rsh* automatically destroys them when it exits. 

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_appl


