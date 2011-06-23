rlogin
=================

The Kerberos V5 *rlogin* command works exactly like the standard UNIX *rlogin* program, with the following Kerberos options added:

============= ================================================================================================================
-f            forwards a copy of your tickets to the remote host.
-F            forwards a copy of your tickets to the remote host, and marks them re-forwardable from the remote host.
-k *realm*    requests tickets for the remote host in the specified realm, instead of determining the realm itself.
-x            encrypts the input and output data streams (the username is sent unencrypted)
============= ================================================================================================================

For example, if *david* wanted to use the standard UNIX *rlogin* to connect to the machine daffodil.example.com, he would type::

     shell% rlogin daffodil.example.com -l david
     Password:  <- david types his password here
     Last login: Fri Jun 21 10:36:32 from :0.0
     Copyright (c) 1980, 1983, 1986, 1988, 1990, 1991, 1993, 1994
             The Regents of the University of California.   All rights reserved.
     
     NetBSD 1.1: Tue May 21 00:31:42 EDT 1996
     
     Welcome to NetBSD!
     shell%

Note that the machine daffodil.example.com asked for *david*'s password. When he typed it, his password was sent over the network unencrypted. If an intruder were watching network traffic at the time, that intruder would know *david*'s password.

If, on the other hand, *jennifer* wanted to use Kerberos V5 *rlogin* to connect to the machine *trillium.mit.edu*, she could forward a copy of her tickets, mark them as not forwardable from the remote host, and request an encrypted session as follows::

     shell% rlogin trillium.mit.edu -f -x
     This rlogin session is using DES encryption for all data transmissions.
     Last login: Thu Jun 20 16:20:50 from daffodil
     Athena Server (sun4) Version 9.1.11 Tue Jul 30 14:40:08 EDT 2002
     shell%

Note that *jennifer*'s machine used Kerberos to authenticate her to *trillium.mit.edu*, and logged her in automatically as herself. She had an encrypted session, a copy of her tickets were waiting for her, and she never typed her password.

If you forwarded your Kerberos tickets, *rlogin* automatically destroys them when it exits.

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_appl




