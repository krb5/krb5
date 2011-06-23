Adding or modifying policies
====================================

To add a new policy, use the kadmin *add_policy* command, which requires the "add" administrative privilege. The syntax is::

     add_policy [options] policy_name
     
*add_policy* has the alias **addpol**.

To modify attributes of a principal, use the kadmin *modify_policy* command, which requires the "modify" administrative privilege. The syntax is::

     modify_policy [options] policy_name
     
*modify_poilcy* has the alias **modpol**.

|

The *add_policy* and *modify_policy* commands take the following switches:

========================= ==================================
-maxlife *time*           Sets the maximum lifetime of a password to time.
-minlife *time*           Sets the minimum lifetime of a password to time.
-minlength *length*       Sets the minimum length of a password to length characters.
-minclasses *number*       Requires at least number of character classes in a password.
-history *number*          Sets the number of past keys kept for a principal to number. This option is not supported for LDAP database. 
========================= ==================================

|

.. note::  The policies are created under *realm* container in the LDAP database. 


------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_policies


