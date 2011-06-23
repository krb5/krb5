Retrieving Policies
========================

To retrieve a policy, use the kadmin *get_policy* command, which requires the "inquire" administrative privilege. The syntax is::

     get_policy [-terse] policy
     

The *get_policy* command has the alias **getpol**.

For example::

     kadmin: get_policy admin
     Policy: admin
     Maximum password life: 180 days 00:00:00
     Minimum password life: 00:00:00
     Minimum password length: 6
     Minimum number of password character classes: 2
     Number of old keys kept: 5
     Reference count: 17
     kadmin:
     

The reference count is the number of principals using that policy.

The *get_policy* command has a *-terse* option, which lists each field as a quoted, tab-separated string. For example::

     kadmin: get_policy -terse admin
     admin   15552000        0       6       2       5       17
     kadmin:
     
------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_policies


