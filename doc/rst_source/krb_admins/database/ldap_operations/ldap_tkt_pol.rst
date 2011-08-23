Ticket Policy operations
===========================

Creating a Ticket Policy
------------------------------------------

To create a new ticket policy in directory , use the :ref:`kdb5_ldap_util(8)` **create_policy** command.
Ticket policy objects are created under the realm container.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_create_policy:
   :end-before: _kdb5_ldap_util_create_policy_end:


Modifying a Ticket Policy
------------------------------------------

To modify a ticket policy in directory , use the :ref:`kdb5_ldap_util(8)` **modify_policy** command.
     
.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_modify_policy:
   :end-before: _kdb5_ldap_util_modify_policy_end:


Retrieving Information About a Ticket Policy
---------------------------------------------


To display the attributes of a ticket policy, use the :ref:`kdb5_ldap_util(8)` **view_policy** command.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_view_policy:
   :end-before: _kdb5_ldap_util_view_policy_end:

     

Destroying a Ticket Policy
--------------------------------

To destroy an existing ticket policy, use the :ref:`kdb5_ldap_util(8)` **destroy_policy** command.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_destroy_policy:
   :end-before: _kdb5_ldap_util_destroy_policy_end:


Listing available Ticket Policies
-----------------------------------

To list the name of ticket policies in a realm, use the :ref:`kdb5_ldap_util(8)` **list_policy** command.

.. include:: ../../admin_commands/kdb5_ldap_util.rst
   :start-after:  _kdb5_ldap_util_destroy_policy:
   :end-before: _kdb5_ldap_util_destroy_policy_end:




     

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_ldap


