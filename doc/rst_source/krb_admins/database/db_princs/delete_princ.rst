Deleting principals
==============================

To delete a principal, use the kadmin *delete_principal* command, which requires the "delete" administrative privilege. The syntax is::

     delete_principal [-force] principal
     
*delete_principal* has the alias **delprinc**. The *-force* option causes *delete_principal* not to ask if you're sure.

For example::

     kadmin: delprinc jennifer
     Are you sure you want to delete the principal
     "jennifer@ATHENA.MIT.EDU"? (yes/no): yes
     Principal "jennifer@ATHENA.MIT.EDU" deleted.
     Make sure that you have removed this principal from
     all ACLs before reusing.
     kadmin:

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_princs

