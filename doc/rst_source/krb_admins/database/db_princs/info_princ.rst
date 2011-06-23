
Retrieving information about a principal
=============================================


Retrieving a list of attributes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To retrieve a listing of the attributes and/or policies associated with a principal, use the kadmin *get_principal* command, which requires the "inquire" administrative privilege. The syntax is::

     get_principal principal
     
The *get_principal* command has the alias **getprinc**.

For example, suppose you wanted to view the attributes of the principal *jennifer/root@ATHENA.MIT.EDU*. You would type::

     shell% kadmin
     kadmin: getprinc jennifer/root
     Principal: jennifer/root@ATHENA.MIT.EDU
     Expiration date: [never]
     Last password change: Mon Jan 31 02:06:40 EDT 2002
     Password Expiration date: [none]
     Maximum ticket life: 0 days 10:00:00
     Maximum renewable life: 7 days 00:00:00
     Last modified: Wed Jul 24 14:46:25 EDT 2002 (joeadmin/admin@ATHENA.MIT.EDU)
     Last successful authentication: Mon Jul 29 18:20:17 EDT 2002
     Last failed authentication: Mon Jul 29 18:18:54 EDT 2002
     Failed password attempts: 3
     Number of keys: 2
     Key: vno 2, Triple DES cbc mode with HMAC/sha1, no salt
     Key: vno 2, DES cbc mode with CRC-32, no salt
     Attributes: DISALLOW_FORWARDABLE, DISALLOW_PROXIABLE
     Policy: [none]
     kadmin:
     
The *get_principal* command has a *-terse* option, which lists the fields as a quoted, tab-separated string. For example::

     kadmin: getprinc -terse jennifer/root
     jennifer/root@ATHENA.MIT.EDU	0	1027458564
     0	36000	 (joeadmin/admin@ATHENA.MIT.EDU
     1027536385	18	2	0	[none]	604800	1027980137
     1027980054	3	2	1	2	16	0	1
     2	1	0
     kadmin:

.. _get_list_princs:
     
Retrieving a list of principals
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To generate a listing of principals, use the kadmin *list_principals* command, which requires the "list" privilege. The syntax is::

     list_principals [expression]
     
where expression is a shell-style glob expression that can contain the characters \*, ?, [, and ]. All policy names matching the expression are displayed. 

The *list_principals* command has the aliases **listprincs, get_principals**, and **getprincs**. For example::

     kadmin: listprincs test*
     test3@ATHENA.MIT.EDU
     test2@ATHENA.MIT.EDU
     test1@ATHENA.MIT.EDU
     testuser@ATHENA.MIT.EDU
     kadmin:
     
If no expression is provided, all principals are printed.

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_princs


