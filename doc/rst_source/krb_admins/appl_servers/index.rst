Application servers
==========================

If you need to install the Kerberos V5 programs on an application server, please refer to the Kerberos V5 Installation Guide. Once you have installed the software, you need to add that host to the Kerberos database (see :ref:`add_mod_del_princs_label`), and generate a keytab for that host, that contains the host's key. You also need to make sure the host's clock is within your maximum clock skew of the KDCs. 


.. toctree::
   :maxdepth: 2

   keytabs.rst
   clock_skew.rst
   dns_info.rst
   conf_firewall.rst

----------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___appl_servers

