eDir: Creating a Service Object
========================================

To create a service object in eDirectory and assign appropriate rights on the container holding kerberos data, use the :ref:`kdb5_ldap_util(8)` **create_service** command.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_create_service:
   :end-before: _kdb5_ldap_util_create_service_end:


eDir: Modifying a Service Object 
=================================

To modify the attributes of a service and assign appropriate rights, if realm associations are changed, use the :ref:`kdb5_ldap_util(8)` **modify_service** command.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_modify_service:
   :end-before: _kdb5_ldap_util_modify_service_end:


eDir: Retrieving Service Object Information
==============================================================

To display the attributes of a service, use the :ref:`kdb5_ldap_util(8)` **view_service** command.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_view_service:
   :end-before: _kdb5_ldap_util_view_service_end:


eDir: Destroying a Service Object
===================================


The :ref:`kdb5_ldap_util(8)` **destroy_service** command is used to destroy an existing service.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_destroy_service:
   :end-before: _kdb5_ldap_util_destroy_service_end:


eDir: Listing Available Service Objects 
===========================================

The :ref:`kdb5_ldap_util(8)` **list_service** command lists the name of services under a given base in eDirectory.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_list_service:
   :end-before: _kdb5_ldap_util_list_service_end:


eDir: Passwords for Service Objects
============================================

The command :ref:`kdb5_ldap_util(8)` **setsrvpw** allows an administrator to set password for service objects such as KDC and Administration server in eDirectory and store them in a file. 

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_setsrvpw:
   :end-before: _kdb5_ldap_util_setsrvpw_end:

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


