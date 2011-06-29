Realm configuration decisions
===============================

.. note:: This document was copied from **Kerberos V5 Installation Guide** with minor changes. Currently it is under review. Please, send your feedback, corrections and additions to krb5-bugs@mit.edu. Your contribution is greatly appreciated.



Before installing Kerberos V5, it is necessary to consider the following issues:

- The name of your Kerberos realm (or the name of each realm, if you need more than one).
- How you will map your hostnames onto Kerberos realms.
- Which ports your KDC and and kadmin (database access) services will use.
- How many slave KDCs you need and where they should be located.
- The hostnames of your master and slave KDCs.
- How frequently you will propagate the database from the master KDC to the slave KDCs. 


Contents:

.. toctree::
   :maxdepth: 2

   realm_name.rst
   mapping_hn.rst
   kdc_ports.rst
   slave_kdc.rst
   kdc_hn.rst
   db_prop.rst


------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___realm_config

