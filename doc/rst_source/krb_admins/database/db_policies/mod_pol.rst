Adding, modifying and deleting policies
===================================================

To add a new policy, use the *kadmin* **add_policy** command.

To modify attributes of a principal, use the *kadmin* **modify_policy** command.

To delete a policy, use the *kadmin* **delete_policy** command.
     
.. include:: ../../admin_commands/kadmin_local.rst
   :start-after:  _add_policy:
   :end-before: _add_policy_end:

.. note::  The policies are created under *realm* container in the LDAP database. 

.. include:: ../../admin_commands/kadmin_local.rst
   :start-after:  _modify_policy:
   :end-before: _modify_policy_end:

.. include:: ../../admin_commands/kadmin_local.rst
   :start-after:  _delete_policy:
   :end-before: _delete_policy_end:

.. note::  You must cancel the policy from *all* principals before deleting it. The *delete_policy* command will fail if it is in use by any principals. 

     


------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_policies


