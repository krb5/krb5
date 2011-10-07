.. _add_mod_del_princs_label:

Adding, modifying and deleting principals
============================================

To add a principal to the database, use the *kadmin* **add_principal** command.

To modify attributes of a principal, use the *kadmin* **modify_principal** command.

To delete a principal, use the *kadmin* **delete_principal** command.


.. include:: ../../admin_commands/kadmin_local.rst
   :start-after:  _add_principal:
   :end-before: _add_principal_end:

.. include:: ../../admin_commands/kadmin_local.rst
   :start-after:  _modify_principal:
   :end-before: _modify_principal_end:

.. include:: ../../admin_commands/kadmin_local.rst
   :start-after:  _delete_principal:
   :end-before: _delete_principal_end:


EXAMPLES
     
If you want to create a principal which is contained by a LDAP object, all you need to do is::

     kadmin: addprinc -x dn=cn=jennifer,dc=example,dc=com jennifer
     WARNING: no policy specified for "jennifer@ATHENA.MIT.EDU";
     defaulting to no policy.
     Enter password for principal jennifer@ATHENA.MIT.EDU:  <= Type the password.
     Re-enter password for principal jennifer@ATHENA.MIT.EDU:  <=Type it again.
     Principal "jennifer@ATHENA.MIT.EDU" created.
     kadmin:
     
If you want to create a principal under a specific LDAP container and link to an existing LDAP object, all you need to do is::

     kadmin: addprinc -x containerdn=dc=example,dc=com -x linkdn=cn=david,dc=example,dc=com david
     WARNING: no policy specified for "david@ATHENA.MIT.EDU";
     defaulting to no policy.
     Enter password for principal david@ATHENA.MIT.EDU:  <= Type the password.
     Re-enter password for principal david@ATHENA.MIT.EDU:  <=Type it again.
     Principal "david@ATHENA.MIT.EDU" created.
     kadmin:
     
If you want to associate a ticket policy to a principal, all you need to do is::

     kadmin: modprinc -x tktpolicy=userpolicy david
     Principal "david@ATHENA.MIT.EDU" modified.
     kadmin:
     
If, on the other hand, you want to set up an account that expires on January 1, 2000, that uses a policy called "stduser", with a temporary password (which you want the user to change immediately), you would type the following::

     
     kadmin: addprinc david -expire "1/1/2000 12:01am EST" -policy stduser +needchange
     Enter password for principal david@ATHENA.MIT.EDU:  <= Type the password.
     Re-enter password for principal
     david@ATHENA.MIT.EDU:  <= Type it again.
     Principal "david@ATHENA.MIT.EDU" created.
     kadmin:
     
If you need cross-realm authentication, you will need to add principals for the other realm's TGT to each realm. For example, if you need to do cross-realm authentication between the realms *ATHENA.MIT.EDU* and *EXAMPLE.COM*, you would need to add the principals *krbtgt\/EXAMPLE.COM\@ATHENA.MIT.EDU* and *krbtgt\/ATHENA.MIT.EDU\@EXAMPLE.COM* to both databases. You need to be sure the passwords and the key version numbers (*kvno*) are the same in both databases. This may require explicitly setting the *kvno* with the *-kvno* option. See :ref:`xrealm_authn_label` for more details.

If you want to delete a principal ::

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


