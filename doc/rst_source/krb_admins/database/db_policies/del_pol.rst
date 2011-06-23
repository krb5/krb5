Deleting policies
========================

To delete a policy, use the kadmin *delete_policy* command, which requires the "delete" administrative privilege. The syntax is::

     delete_policy [-force] policy_name
     

The *delete_policy* command has the alias **delpol**. It prompts for confirmation before deletion. 

For example::

     kadmin: delete_policy guests
     Are you sure you want to delete the policy "guests"?
     (yes/no): yes
     kadmin:
     
.. note::  You must cancel the policy from *all* principals before deleting it. The *delete_policy* command will fail if it is in use by any principals. 


     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_policies

