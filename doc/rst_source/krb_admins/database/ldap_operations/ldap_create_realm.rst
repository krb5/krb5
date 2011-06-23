.. _ldap_create_realm_label:

Creating a Kerberos realm
================================

If you need to create a new realm, use the command as follows::

     
     create  [-r realm]  [-subtrees subtree_dn_list] [-sscope search_scope] [-containerref container_reference_dn]
     [-k  mkeytype] [-m|-P password][-sf stashlename] [-s] [-maxtktlife max_ticket_life]
     [-maxrenewlife  max_renewable_ticket_life] [ticket_flags]
     
     

Options to create realm in directory are as follows

=========================================== ==============================================
-r *realm*                                   Specifies the Kerberos realm of the database; by default the realm returned by krb5_default_local_realm (3) is used. 
-subtrees *subtree_dn_list*                  Specifies the list of subtrees containing principals of a realm. The list contains the DN of the subtree objects separated by colon(:). 
-sscope *search_scope*                          Specifies the scope for searching the principals under the subtree. The possible values are 1 or one (one level), 2 or sub (subtree). 
-containerref *container_reference_dn*            Specfies the DN of the container object in which the principals of a realm will be created. If the container reference is not configured for a realm, the principals will be created in the realm container. 
-k *mkeytype*                                  Specifies the key type of the master key in the database; the default is that given in kdc.conf. 
-m                                              Specifies that the master database password should be read from the TTY rather than fetched from a file on disk. 
-p *password*                                    Specifies the master database password. This option is not recommended. 
-sf *stashfilename*                            Specifies the stash file of the master database password. 
-s                                              Specifies that the stash file is to be created. 
-maxtktlife *max_ticket_life*                    Specifies maximum ticket life for principals in this realm. This value is used, if it is not set on the principal. 
-maxrenewlife *max_renewable_ticket_life*      Specifies maximum renewable life of tickets for principals in this realm. This value is used, if it is not set on the principal. 
ticket_flags                                    Specifies the ticket flags_. If this option is not specified, by default, none of the flags are set. This means all the ticket options will be allowed and no restriction will be set. This value is used, if it is not set on the principal. 
=========================================== ==============================================

.. _flags:

The various **ticket flags** are:

    {-\|+}allow_postdated
        -allow_postdated prohibits principals from obtaining postdated tickets. (Sets the KRB5_KDB_DISALLOW_POSTDATED flag.).+allow_postdated clears this flag. 
    {-\|+}allow_forwardable
        -allow_forwardable prohibits principals from obtaining forwardable tickets. (Sets the KRB5_KDB_DISALLOW_FORWARDABLE flag.) +allow_forwardable clears this flag. 
    {-\|+}allow_renewable
        -allow_renewable prohibits principals from obtaining renewable tickets. (Sets the KRB5_KDB_DISALLOW_RENEWABLE flag.) +allow_renewable clears this flag. 
    {-\|+}allow_proxiable
        -allow_proxiable prohibits principals from obtaining proxiable tickets. (Sets the KRB5_KDB_DISALLOW_PROXABLE flag.) +allow_proxiable clears this flag. 
    {-\|+}allow_dup_skey
        -allow_dup_skey disables user-to-user authentication for principals by prohibiting principals from obtaining a sessions key for another user. (Sets the KRB5_KDB_DISALLOW_DUP_SKEY flag.) +allow_dup_skey clears this flag. 
    {-\|+}requires_preauth
        +requires_preauth requires principals to preauthenticate before being allowed to kinit. (Sets the KRB5_KDB_REQURES_PRE_AUTH flag.) -requires_preauth clears this flag. 
    {-\|+}requires_hwauth
        +requires_hwauth requires principals to preauthenticate using a hardware device before being allowed to kinit. (Sets the KRB5_KDB_REQURES_HW_AUTH flag.) -requires_hwauth clears this flag. 
    {-\|+}ok_as_delegate
        +ok_as_delegate sets the OK-AS-DELEGATE flag on tickets issued for use with this principal as the service, which clients may use as a hint that credentials can and should be delegated when authenticating to the service. (Sets the KRB5_KDB_OK_AS_DELEGATE flag.) -ok_as_delegate clears this flag. 
    {-\|+}allow_svr
        -allow_svr prohibits the issuance of service tickets for principals. (Sets the KRB5_KDB_DISALLOW_SVR flag.) +allow_svr clears this flag. 
    {-\|+}allow_tgs_req
        -allow_tgs_req specifies that a Ticket-Granting Service (TGS) request for a service ticket for principals is not permitted. This option is useless for most things.+allow_tgs_req clears this flag. The default is +allow_tgs_req. In effect, -allow_tgs_req sets the KRB5_KDB_DISALLOW_TGT_BASED flag on principals in the database. 
    {-\|+}allow_tix
        -allow_tix forbids the issuance of any tickets for principals. +allow_tix clears this flag. The default is +allow_tix. In effect, -allow_tix sets the KRB5_KDB_DISALLOW_ALL_TIX flag on principals in the database. 
    {-\|+}needchange
        +needchange sets a flag in attributes field to force a password change; -needchange clears it. The default is -needchange. In effect, +needchange sets the KRB5_KDB_REQURES_PWCHANGE flag on principals in the database. 
    {-\|+}password_changing_service
        +password_changing_service sets a flag in the attributes field marking principal as a password change service principal (useless for most things). -password_changing_service clears the flag. This flag intentionally has a long name. The default is -password_changing_service. In effect, +password_changing_service sets the KRB5_KDB_PWCHANGE_SERVICE flag on principals in the database. 

|

For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu create -sscope 2
     -subtree ou=users,dc=example,dc=com -r ATHENA.MIT.EDU
     Password for "cn=admin,dc=example,dc=com":
     Initializing database for realm 'ATHENA.MIT.EDU'
     You will be prompted for the database Master Password.
     It is important that you NOT FORGET this password.
     Enter KDC database master key:
     Re-enter KDC database master key to verify:
     shell%
     


.. seealso:: :ref:`edir_create_realm_label`

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_ldap

