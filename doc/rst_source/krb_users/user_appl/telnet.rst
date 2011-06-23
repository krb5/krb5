telnet
=================

The Kerberos  V5 telnet command works exactly like the standard UNIX telnet program, with the following Kerberos options added:

============== ==========================================================================================================================
-f             forwards a copy of your tickets to the remote host.
-F             forwards a copy of your tickets to the remote host, and marks them re-forwardable from the remote host.
-k *realm*     requests tickets for the remote host in the specified realm, instead of determining the realm itself.
-K             uses your tickets to authenticate to the remote host, but does not log you in.
-a             attempt automatic login using your tickets. telnet will assume the same username unless you explicitly specify another.
-x             turns on encryption.
============== ==========================================================================================================================

For example, if david wanted to use the standard UNIX telnet to connect to the machine daffodil.mit.edu, he would type::

     shell% telnet daffodil.example.com
     Trying 128.0.0.5 ...
     Connected to daffodil.example.com.
     Escape character is '^]'.
     
     NetBSD/i386 (daffodil) (ttyp3)
     
     login: david
     Password:    <- david types his password here
     Last login: Fri Jun 21 17:13:11 from trillium.mit.edu
     Copyright (c) 1980, 1983, 1986, 1988, 1990, 1991, 1993, 1994
             The Regents of the University of California.   All rights reserved.
     
     NetBSD 1.1: Tue May 21 00:31:42 EDT 1996
     
     Welcome to NetBSD!
     shell%

Note that the machine *daffodil.example.com* asked for *david*'s password. When he typed it, his password was sent over the network unencrypted. If an intruder were watching network traffic at the time, that intruder would know david's password.

If, on the other hand, *jennifer* wanted to use the Kerberos V5 telnet to connect to the machine *trillium.mit.edu*, she could forward a copy of her tickets, request an encrypted session, and log on as herself as follows::

     shell% telnet -a -f -x trillium.mit.edu
     Trying 128.0.0.5...
     Connected to trillium.mit.edu.
     Escape character is '^]'.
     [ Kerberos V5 accepts you as ``jennifer@mit.edu'' ]
     [ Kerberos V5 accepted forwarded credentials ]
     What you type is protected by encryption.
     Last login: Tue Jul 30 18:47:44 from daffodil.example.com
     Athena Server (sun4) Version 9.1.11 Tue Jul 30 14:40:08 EDT 2002
     
     shell%

Note that *jennifer*'s machine used Kerberos to authenticate her to *trillium.mit.edu*, and logged her in automatically as herself. She had an encrypted session, a copy of her tickets already waiting for her, and she never typed her password.

If you forwarded your Kerberos tickets, *telnet* automatically destroys them when it exits. 

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_appl


