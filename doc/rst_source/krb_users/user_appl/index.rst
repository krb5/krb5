Kerberized LINUX/UNIX applications
====================================

.. note:: This document was copied from **Kerberos V5 UNIX User's Guide**. Currently it is under review. Please, send your feedback, corrections and additions to krb5-bugs@mit.edu. Your contribution is greatly appreciated.



Kerberos V5 is a single-sign-on system. This means that you only have to type your password once, and the Kerberos V5 programs do the authenticating (and optionally encrypting) for you. The way this works is that Kerberos has been built into each of a suite of network programs. For example, when you use a Kerberos V5 program to connect to a remote host, the program, the KDC, and the remote host perform a set of rapid negotiations. When these negotiations are completed, your program has proven your identity on your behalf to the remote host, and the remote host has granted you access, all in the space of a few seconds.o

The Kerberos V5 network programs are those programs that connect to another host somewhere on the internet. These programs include rlogin, telnet, ftp, rsh, rcp, and ksu. These programs have all of the original features of the corresponding non-Kerberos rlogin, telnet, ftp, rsh, rcp, and su programs, plus additional features that transparently use your Kerberos tickets for negotiating authentication and optional encryption with the remote host. In most cases, all you'll notice is that you no longer have to type your password, because Kerberos has already proven your identity.

The Kerberos V5 network programs allow you the options of forwarding your tickets to the remote host (if you obtained forwardable tickets with the *kinit* program; see :ref:`otwk_labal`), and encrypting data transmitted between you and the remote host.

The Kerberos V5 applications are versions of existing UNIX network programs with the Kerberos features added.

.. toctree::
   :maxdepth: 1

   telnet.rst
   ftp.rst
   rcp.rst
   rlogin.rst
   rsh.rst
   ksu.rst
   ssh.rst


------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_appl


