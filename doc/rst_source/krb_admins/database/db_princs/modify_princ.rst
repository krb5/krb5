.. _add_mod_princs_label:

Adding or modifying principals
===================================

To add a principal to the database, use the kadmin *add_principal* command, which requires the "add" administrative privilege. This function creates the new principal, prompting twice for a password, and, if neither the *-policy* nor *-clearpolicy* options are specified and the policy "default" exists, assigns it that policy. The syntax is::

     kadmin: add_principal [options] principal
     
*add_principali* has the aliases **addprinc** and **ank2**. 


To modify attributes of a principal, use the kadmin *modify_principal* command, which requires the "modify" administrative privilege. The syntax is::

     kadmin: modify_principal [options] principal
     
*modify_principal* has the alias **modprinc**.

|

The *add_principal* and *modify_principal* commands take the following switches:

*-x db_princ_args*
Denotes the database specific options.

The options for LDAP database are:

*-x dn=<dn>*
Specifies the LDAP object that will contain the Kerberos principal being created. 

*-x linkdn=<dn>*
Specifies the LDAP object to which the newly created Kerberos principal object will point to. 

*-x containerdn=<container_dn>*
Specifies the container object under which the Kerberos principal is to be created. 

*-x tktpolicy=<policy>*
Associates a ticket policy to the Kerberos principal. Specifying an empty string value clears the ticket policy associated with the principal.

.. note:: 
        - *dn* and *containerdn* options are not valid while modifying the principal.
        - *containerdn* and *linkdn* options cannot be specified with dn option.  
        - If *dn* or *containerdn* options are not specified while adding the principal, the principals are created under the prinicipal container configured in the realm or the realm container. 
        - *dn* and *containerdn* should be within the subtrees or principal container configured in the realm.

*-expire date*
Sets the expiration date of the principal to date. 

*-pwexpire date*
Sets the expiration date of the password to date. 

*-maxlife maxlife*
Sets the maximum ticket life of the principal to maxlife. 

*-maxrenewlife maxrenewlife*
Sets the maximum renewable life of tickets for the principal to maxrenewlife. 

*-kvno number*
Explicity sets the key version number to number. MIT does not recommend doing this unless there is a specific reason. 

*-policy policy*
Sets the policy used by this principal. (See :ref:`db_policies_label`) With *modify_principal*, the current policy assigned to the principal is set or changed. With *add_principal*, if this option is not supplied, the *-clearpolicy* is not specified, and the policy "default" exists, that policy is assigned. If a principal is created with no policy, kadmin will print a warning message. 

*-clearpolicy*
For *modify_principal*, removes the current policy from a principal. For *add_principal*, suppresses the automatic assignment of the policy "default". 

*{-|+}allow_postdated*
The "-allow_postdated" option prohibits this principal from obtaining postdated tickets. "+allow_postdated" clears this flag. In effect, "-allow_postdated" sets the KRB5_KDB_DISALLOW_POSTDATED flag on the principal in the database. 

*{-|+}allow_forwardable*
The "-allow_forwardable" option prohibits this principal from obtaining forwardable tickets. "+allow_forwardable" clears this flag. In effect, "-allow_forwardable" sets the KRB5_KDB_DISALLOW_FORWARDABLE flag on the principal in the database. 

*{-|+}allow_renewable*
The "-allow_renewable" option prohibits this principal from obtaining renewable tickets. "+allow_renewable" clears this flag. In effect, "-allow_renewable" sets the KRB5_KDB_DISALLOW_RENEWABLE flag on the principal in the database. 

*{-|+}allow_proxiable*
The "-allow_proxiable" option prohibits this principal from obtaining proxiable tickets. "+allow_proxiable" clears this flag. In effect, "-allow_proxiable" sets the 
KRB5_KDB_DISALLOW_PROXIABLE flag. on the principal in the database. 

*{-|+}allow_dup_skey*
The "-allow_dup_skey" option disables user-to-user authentication for this principal by prohibiting this principal from obtaining a session key for another user. "+allow_dup_skey" clears this flag. In effect, "-allow_dup_skey" sets the 
KRB5_KDB_DISALLOW_DUP_SKEY flag on the principal in the database. 

*{-|+}requires_preauth*
The "+requires_preauth" option requires this principal to preauthenticate before being allowed to kinit. -requires_preauth clears this flag. In effect, +requires_preauth sets the KRB5_KDB_REQUIRES_PRE_AUTH flag on the principal in the database. 

*{-|+}requires_hwauth*
The "+requires_hwauth" flag requires the principal to preauthenticate using a hardware device before being allowed to kinit. "-requires_hwauth" clears this flag. In effect, "+requires_hwauth" sets the KRB5_KDB_REQUIRES_HW_AUTH flag on the principal in the database. 

*{-|+}allow_svr*
The "-allow_svr" flag prohibits the issuance of service tickets for this principal. "+allow_svr" clears this flag. In effect, "-allow_svr" sets the 
KRB5_KDB_DISALLOW_SVR flag on the principal in the database. 

*{-|+}allow_tgs_req*
The "-allow_tgs_req" option specifies that a Ticket-Granting Service (TGS) request for a service ticket for this principal is not permitted. You will probably never need to use this option. "+allow_tgs_req" clears this flag. The default is "+allow_tgs_req". In effect, "-allow_tgs_req" sets the KRB5_KDB_DISALLOW_TGT_BASED flag on the principal in the database. 

*{-|+}allow_tix*
The "-allow_tix" option forbids the issuance of any tickets for this principal. "+allow_tix" clears this flag. The default is "+allow_tix". In effect, "-allow_tix" sets the 
KRB5_KDB_DISALLOW_ALL_TIX flag on the principal in the database. 

*{-|+}needchange*
The "+needchange" option sets a flag in attributes field to force a password change; "-needchange" clears it. The default is "-needchange". In effect, "+needchange" sets the KRB5_KDB_REQUIRES_PWCHANGE flag on the principal in the database. 

*{-|+}password_changing_service*
The "+password_changing_service" option sets a flag in the attributes field marking this principal as a password change service. (Again, you will probably never need to use this option.) "-password_changing_service" clears the flag. The default is "-password_changing_service". In effect, the "+password_changing_service" option sets the KRB5_KDB_PWCHANGE_SERVICE flag on the principal in the database. 

*{-|+}ok_as_delegate*
The "+ok_as_delegate" option sets a flag in tickets issued for the service principal. Some client programs may recognize this flag as indicating that it is okay to delegate credentials to the service. If ok_as_delegate is set on a cross-realm TGT, it indicates that the foreign realm's ok_as_delegate flags should be honored by clients in the local realm. The default is "-ok_as_delegate". 

*-randkey*
Sets the key for the principal to a random value (*add_principal* only). MIT recommends using this option for host keys. 

*-pw password*
Sets the key of the principal to the specified string and does not prompt for a password (*add_principal* only). MIT does not recommend using this option. 

*-e enc:salt...*
Uses the specified list of enctype-salttype pairs for setting the key of the principal. The quotes are necessary if there are multiple enctype-salttype pairs. This will not function against kadmin daemons earlier than krb5-1.2. See :ref:`Supported_Encryption_Types_and_Salts` for available types.


If you want to just use the default values, all you need to do is::

     kadmin: addprinc jennifer
     WARNING: no policy specified for "jennifer@ATHENA.MIT.EDU";
     defaulting to no policy.
     Enter password for principal jennifer@ATHENA.MIT.EDU:  <= Type the password.
     Re-enter password for principal jennifer@ATHENA.MIT.EDU:  <=Type it again.
     Principal "jennifer@ATHENA.MIT.EDU" created.
     kadmin:
     
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
     
If, on the other hand, you want to set up an account that expires on January 1, 2000, that uses a policy called "stduser", with a temporary password (which you want the user to change immediately), you would type the following. (Note: each line beginning with => is a continuation of the previous line.)::

     
     kadmin: addprinc david -expire "1/1/2000 12:01am EST" -policy stduser
     =>  +needchange
     Enter password for principal david@ATHENA.MIT.EDU:  <= Type the password.
     Re-enter password for principal
     david@ATHENA.MIT.EDU:  <= Type it again.
     Principal "david@ATHENA.MIT.EDU" created.
     kadmin:
     
If you need cross-realm authentication, you will need to add principals for the other realm's TGT to each realm. For example, if you need to do cross-realm authentication between the realms *ATHENA.MIT.EDU* and *EXAMPLE.COM*, you would need to add the principals *krbtgt\/EXAMPLE.COM\@ATHENA.MIT.EDU* and *krbtgt\/ATHENA.MIT.EDU\@EXAMPLE.COM* to both databases. You need to be sure the passwords and the key version numbers (*kvno*) are the same in both databases. This may require explicitly setting the *kvno* with the *-kvno* option. See :ref:`xrealm_authn_label` for more details.


------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_princs


