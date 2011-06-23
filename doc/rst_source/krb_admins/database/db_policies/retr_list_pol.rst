Retrieving the list of policies
==================================

You can retrieve the list of policies with the kadmin *list_policies* command, which requires the "list" privilege. The syntax is::

     list_policies [expression]
     

where expression is a shell-style glob expression that can contain the characters \*, ?, and []. All policy names matching the expression are displayed. 

The *list_policies* command has the aliases **listpols, get_policies**, and **getpols**. 

For example::

     kadmin:  listpols
     test-pol
     dict-only
     once-a-min
     test-pol-nopw
     
     kadmin:  listpols t*
     test-pol
     test-pol-nopw
     kadmin:
     

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_policies


