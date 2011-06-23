Ticket Policy operations
===========================

Creating and modifying a Ticket Policy
------------------------------------------


This command creates a ticket policy in directory::

     create_policy [-r realm] [-maxrenewlife max_renewable_ticket_life] [ticket_flags] policy_name
     

Ticket policy objects are created under the realm container.

This command modifies a ticket policy in directory::

     modify_policy [-r realm] [-maxrenewlife max_renewable_ticket_life] [ticket_flags] policy_name
     

Options are as follows

=========================================== =========================================================
-r *realm*                                    Specifies the Kerberos realm of the database; by default the realm returned by krb5_default_local_realm(3) is used. 
-maxtktlife *max_ticket_life*                 Specifies maximum ticket life for principals. 
-maxrenewlife *max_renewable_ticket_life*     Specifies maximum renewable life of tickets for principals. 
ticket_flags                                Specifies the ticket flags_. If this option is not specified, by default, none of the flags are set. This means all the ticket options will be allowed and no restriction will be set.
policy_name                                   Specifies the name of the ticket policy. 
=========================================== =========================================================

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
        -allow_dup_skey Disables user-to-user authentication for principals by prohibiting principals from obtaining a sessions key for another user. (Sets the KRB5_KDB_DISALLOW_DUP_SKEY flag.). +allow_dup_skey clears This flag. 
    {-\|+}requires_preauth
        +requires_preauth requires principals to preauthenticate before being allowed to kinit. (Sets the KRB5_KDB_REQURES_PRE_AUTH flag.) -requires_preauth clears this flag. 
    {-\|+}requires_hwauth
        +requires_hwauth requires principals to preauthenticate using a hardware device before being allowed to kinit. (Sets the KRB5_KDB_REQURES_HW_AUTH flag.) -requires_hwauth clears this flag. 
    {-\|+}allow_svr
        -allow_svr prohibits the issuance of service tickets for principals. (Sets the KRB5_KDB_DISALLOW_SVR flag.) +allow_svr clears This flag. 
    {-\|+}allow_tgs_req
        -allow_tgs_req specifies that a Ticket-Granting Service (TGS) request for a service ticket for principals is not permitted. This option is useless for most things.+allow_tgs_req clears this flag. The default is +allow_tgs_req. In effect, -allow_tgs_req sets the KRB5_KDB_DISALLOW_TGT_BASED flag on principals in the database. 
    {-\|+}allow_tix
        -allow_tix forbids the issuance of any tickets for principals. +allow_tix clears this flag. The default is +allow_tix. In effect, -allow_tix sets the KRB5_KDB_DISALLOW_ALL_TIX flag on principals in the database. 
    {-\|+}needchange
        +needchange sets a flag in attributes field to force a password change; -needchange clears it. The default is -needchange. In effect, +needchange sets the KRB5_KDB_REQURES_PWCHANGE flag on principals in the database. 
    {-\|+}password_changing_service
        +password_changing_service sets a flag in the attributes field marking principal as a password change service principal (useless for most things). -password_changing_service clears the flag. This flag intentionally has a long name. The default is -password_changing_service. In effect, +password_changing_service sets the KRB5_KDB_PWCHANGE_SERVICE flag on principals in the database. 


For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu create_policy
     -r ATHENA.MIT.EDU -maxtktlife "1 day" -maxrenewlife "1 week" -allow_forwardable usertktpolicy


     Password for "cn=admin,dc=example,dc=com":
     shell%
     

Retrieving Information About a Ticket Policy
---------------------------------------------


To display the attributes of a ticket policy, use the following command::

   view_policy [-r realm] policy_name

Options are as follows

=============== ==========================
-r *realm*            Specifies the Kerberos realm of the database; by default the realm returned by krb5_default_local_realm(3) is used. 
policy_name       Specifies the name of the ticket policy
=============== ==========================


For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu view_policy
     -r ATHENA.MIT.EDU usertktpolicy


     Password for "cn=admin,dc=example,dc=com":
     Ticket policy: usertktpolicy
     Maxmum ticket life: 0 days 01:00:00
     Maxmum renewable life: 0 days 10:00:00
     Ticket flags: DISALLOW_FORWARDABLE REQUIRES_PWCHANGE
     shell%
     

Destroying a Ticket Policy
--------------------------------

To destroy an existing ticket policy, use the following command::

   destroy_policy [-force] [-r realm] policy_name


Options are as follows

=============== =========================================================
-force            Forces the deletion of the policy object. If not specified, will be prompted for confirmation while deleting the policy. Enter yes to confirm the deletion. 
-r *realm*           Specifies the Kerberos realm of the database; by default the realm returned by krb5_default_local_realm(3) is used. 
policy_name        Specifies the name of the ticket policy. 
=============== =========================================================


For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu
     destroy_policy -r ATHENA.MIT.EDU usertktpolicy


     Password for "cn=admin,dc=example,dc=com":
     This will delete the policy object 'usertktpolicy', are you sure?
     (type 'yes' to confirm)? Yes
     ** policy object 'usertktpolicy' deleted.
     shell%
     

Listing available Ticket Policies
-----------------------------------

To list the name of ticket policies in a realm, use the fillowing command::

   list_policy [-r realm]

Option is as follows: 

-r *realm*
    Specifies the Kerberos realm of the database; by default the realm returned by krb5_default_local_realm(3) is used. 


For example::

     shell% kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldaps://ldap-server1.mit.edu list_policy -r ATHENA.MIT.EDU


     Password for "cn=admin,dc=example,dc=com":
     usertktpolicy
     tempusertktpolicy
     krbtktpolicy
     shell%
     

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_ldap


