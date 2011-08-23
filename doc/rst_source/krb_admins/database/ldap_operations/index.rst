.. _ops_on_ldap_label:

Operations on the LDAP database
===================================================

The *kdb5_ldap_util* is the primary tool for administrating the Kerberos LDAP database. It allows an administrator to manage realms, Kerberos services ( KDC and Admin Server) and ticket policies.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_synopsis:
   :end-before: _kdb5_ldap_util_synopsis_end:

**OPTIONS**

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_options:
   :end-before: _kdb5_ldap_util_options_end:




LDAP
----------

.. toctree::
   :maxdepth: 2

   ldap_create_realm.rst
   ldap_mod_realm.rst
   ldap_del_realm.rst
   ldap_realm_info.rst
   ldap_realm_list.rst
   ldap_stash_pass.rst
   ldap_tkt_pol.rst


eDirectory
-----------

.. toctree::
   :maxdepth: 1

   edir_create_realm.rst
   edir_create_so.rst


