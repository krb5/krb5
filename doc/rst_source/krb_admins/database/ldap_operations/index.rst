.. _ops_on_ldap_label:

Operations on the LDAP database
===================================================

The *kdb5_ldap_util* is the primary tool for administrating the Kerberos LDAP database. It allows an administrator to manage realms, Kerberos services ( KDC and Admin Server) and ticket policies.

The syntax is::

     kdb5_ldap_util [-D user_dn [-w passwd]] [-H ldap_uri] command [command_options]
     
======================= ====================================================
-D *user_dn*              Specifies the Distinguished Name (DN) of the user who has sufficient rights to perform the operation on the LDAP server. 
-w *passwd*              Specifies the password of *user_dn*. This option is not recommended. 
-H *ldap_uri*            Specifies the URI of the LDAP server. It is recommended to use *ldapi://* or *ldaps://* to connect to the LDAP server. 
======================= ====================================================


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
   edir_mod_realm.rst
   edir_create_so.rst
   edir_mod_so.rst
   edir_get_so.rst
   edir_del_so.rst
   edir_so_list.rst
   edir_so_pass.rst


