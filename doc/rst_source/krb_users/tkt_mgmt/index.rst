Ticket management
============================

.. note:: This document was copied from **Kerberos V5 UNIX User's Guide**. Currently it is under review. Please, send your feedback, corrections and additions to krb5-bugs@mit.edu. Your contribution is greatly appreciated.



On many systems, Kerberos is built into the login program, and you get tickets automatically when you log in. Other programs, such as *rsh, rcp, telnet*, and *rlogin*, can forward copies of your tickets to the remote host. Most of these programs also automatically destroy your tickets when they exit. However, MIT recommends that you explicitly destroy your Kerberos tickets when you are through with them, just to be sure. One way to help ensure that this happens is to add the *kdestroy* command to your *.logout* file. Additionally, if you are going to be away from your machine and are concerned about an intruder using your permissions, it is safest to either destroy all copies of your tickets, or use a screensaver that locks the screen.

.. toctree::
   :maxdepth: 1

   tkt_management.rst
   obtain_kinit.rst
   view_klist.rst
   destroy_tkt.rst

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_tkt_mgmt

