Installing and configuring UNIX client machines
=====================================================

The Kerberized client programs are *kinit, klist, kdestroy, kpasswd,* and *ksu*. All of these programs are in the directory */usr/local/bin*. MIT recommends that you use login.krb5 in place of /bin/login to give your users a single-sign-on system. You will need to make sure your users know to use their Kerberos passwords when they log in.

You will also need to educate your users to use the ticket management programs *kinit, klist, kdestroy,* and to use the Kerberos programs *ksu* and *kpasswd* in place of their non-Kerberos counterparts *su* and *passwd*. 

.. toctree::
   :maxdepth: 1

   cl_config.rst
   mac_osX_config.rst

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___cl_install



