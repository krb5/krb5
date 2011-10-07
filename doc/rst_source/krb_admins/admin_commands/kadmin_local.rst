.. _kadmin(1):

.. _kadmin.local(1):

kadmin, kadmin.local
===========================


SYNOPSYS
--------------

.. _kadmin_synopsys:
      
**kadmin** 
         [ **-O** | **-N** ] 
         [**-r** *realm*] 
         [**-p** *principal*] 
         [**-q** *query*]
         [[**-c** *cache_name*] | [**-k** [**-t** *keytab* ]] | **-n**]
         [**-w** *password*] 
         [**-s** *admin_server* [:*port*]]


**kadmin.local**
                 [**-r** *realm*]
                 [**-p** *principal*] 
                 [**-q** *query*]
                 [**-d** *dbname*] 
                 [**-e** "enc:salt ..."] 
                 [**-m**] 
                 [**-x** *db_args*]


.. _kadmin_synopsys_end:
      
DESCRIPTION
------------

*kadmin* and *kadmin.local* are command-line interfaces to the Kerberos V5 KADM5 administration system.
Both *kadmin* and *kadmin.local* provide identical functionalities; 
the difference is that *kadmin.local* runs on the master KDC if the database is db2 and does not use Kerberos to authenticate to the database. 
Except as explicitly noted otherwise, this man page will use *kadmin* to refer to both versions.
*kadmin* provides for the maintenance of Kerberos principals, KADM5 policies, and service key tables (keytabs).

The remote version uses Kerberos authentication and an encrypted RPC, to operate securely from anywhere on the network.   
It authenticates to the KADM5 server using the service principal *kadmin/admin*.  
If the credentials cache contains a ticket for the *kadmin/admin* principal, and the *-c* credentials_cache option is specified, 
that ticket is used to authenticate to KADM5.  
Otherwise, the *-p* and *-k* options are used to specify the client Kerberos principal name used to authenticate.  
Once *kadmin* has determined the principal name, it requests a *kadmin/admin* Kerberos service ticket from the KDC, 
and uses that service ticket to authenticate to KADM5.

If the database is db2, the local client *kadmin.local* is intended to run directly on the master KDC without Kerberos authentication.
The local version provides all of the functionality of the now obsolete kdb5_edit(8), except for database dump and load, 
which is now provided by the :ref:`kdb5_util(8)` utility.

If the database is LDAP, *kadmin.local* need not be run on the KDC.

*kadmin.local* can be configured to log updates for incremental database propagation.  
Incremental propagation allows slave KDC servers to receive principal and policy updates incrementally instead of receiving full dumps of the database.  
This facility can be enabled in the :ref:`kdc.conf` file with the *iprop_enable* option.  
See the :ref:`kdc.conf` documentation for other options for tuning incremental propagation parameters.


OPTIONS
------------

.. _kadmin_options:

       **-r** *realm*
              Use *realm* as the default database realm.

       **-p** *principal*
              Use  *principal* to authenticate.  Otherwise, *kadmin* will append "/admin" to the primary principal name of the default ccache, the
              value of the *USER* environment variable, or the username as obtained with *getpwuid*, in order of preference.

       **-k**     
              Use a *keytab* to decrypt the KDC response instead of prompting for a password on the TTY.  In this case, the default principal
              will be *host/hostname*.  If there is not a *keytab* specified with the **-t** option, then the default *keytab* will be used.

       **-t** *keytab*
              Use *keytab* to decrypt the KDC response.  This can only be used with the **-k** option.  

       **-n**
              Requests anonymous processing.  Two types of anonymous principals are supported.  
              For fully anonymous Kerberos, configure pkinit on the KDC and configure *pkinit_anchors* in the client's :ref:`krb5.conf`.  
              Then use the *-n* option with a principal of the form *@REALM* (an empty principal name followed by the at-sign and a realm name).  
              If permitted by the KDC, an anonymous ticket will be returned.  
              A second form of anonymous tickets is supported; these realm-exposed tickets hide the identity of the client but not the client's realm.  
              For this mode, use *kinit -n* with a normal principal name.  
              If supported by the KDC, the principal (but not realm) will be replaced by the anonymous principal.  
              As of release 1.8, the MIT Kerberos KDC only supports fully anonymous operation.

       **-c** *credentials_cache*
              Use *credentials_cache* as the credentials cache.  The *credentials_cache* should contain a service ticket for the *kadmin/admin* service; 
              it can be acquired with the :ref:`kinit(1)` program.  If this option is not specified, *kadmin* requests a new service ticket from
              the KDC, and stores it in its own temporary ccache.

       **-w** *password*
              Use *password* instead of prompting for one on the TTY. 
          
              .. note::  Placing the password for a Kerberos principal with administration access into a shell script can be dangerous if 
                         unauthorized users gain read access to the script.

       **-q** *query*
              pass query directly to kadmin, which will perform query and then exit.  This can be useful for writing scripts.

       **-d** *dbname*
              Specifies the name of the Kerberos database.  This option does not apply to the LDAP database.

       **-s** *admin_server* [:port]
              Specifies the admin server which *kadmin* should contact.

       **-m**     Do not authenticate using a *keytab*.  This option will cause *kadmin* to prompt for the master database password.

       **-e** enc:salt_list
              Sets the list of encryption types and salt types to be used for any new keys created.

       **-O**     Force use of old AUTH_GSSAPI authentication flavor.

       **-N**     Prevent fallback to AUTH_GSSAPI authentication flavor.

       **-x** *db_args*
              Specifies the database specific arguments.

              Options supported for LDAP database are:

              **-x** host=<hostname>
                     specifies the LDAP server to connect to by a LDAP URI.

              **-x** binddn=<bind_dn>
                     specifies the DN of the object used by the administration server to bind to the LDAP server.  This object should have the
                     read and write rights on the realm container, principal container and the subtree that is referenced by the realm.

              **-x** bindpwd=<bind_password>
                     specifies the password for the above mentioned binddn. It is recommended not to use this option.  
                     Instead, the password can be stashed using the *stashsrvpw* command of :ref:`kdb5_ldap_util(8)`


.. _kadmin_options_end:


DATE FORMAT
--------------

.. _date_format:

Many of the *kadmin* commands take a duration or time as an argument. The date can appear in a wide variety of formats, such as::

              1 month ago
              2 hours ago
              400000 seconds ago
              last year
              this Monday
              next Monday
              yesterday
              tomorrow
              now
              second Monday
              fortnight ago
              3/31/92 10:00:07 PST
              January 23, 1987 10:05pm
              22:00 GMT

Dates which do not have the "ago" specifier default to being absolute dates, unless they appear in a field where a duration is expected.   
In that case the time specifier will be interpreted as relative.  
Specifying "ago" in a duration may result in unexpected behavior.


The following is a list of all of the allowable keywords.

========================== ============================================
Months                      january, jan, february, feb, march, mar, april, apr, may, june, jun, july, jul, august, aug, september, sep, sept, october, oct, november, nov, december, dec 
Days                        sunday, sun, monday, mon, tuesday, tues, tue, wednesday, wednes, wed, thursday, thurs, thur, thu, friday, fri, saturday, sat 
Units                       year, month, fortnight, week, day, hour, minute, min, second, sec 
Relative                    tomorrow, yesterday, today, now, last, this, next, first, second, third, fourth, fifth, sixth, seventh, eighth, ninth, tenth, eleventh, twelfth, ago 
Time Zones                  kadmin recognizes abbreviations for most of the world's time zones. A complete listing appears in kadmin Time Zones. 
12-hour Time Delimiters     am, pm
========================== ============================================

.. _date_format_end:



COMMANDS
-----------

.. _add_principal:

add_principal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **add_principal** [options] *newprinc*
              creates the principal *newprinc*, prompting twice for a password.  If no policy is specified with the *-policy* option, 
              and the policy named "default" exists, then that policy is assigned to the principal; 
              note that the assignment of the policy "default" only occurs automatically when a principal is first created, 
              so the policy "default" must already exist for the assignment to occur.
              This assignment of "default" can be suppressed with the *-clearpolicy* option. 

                .. note:: This command requires the *add* privilege. 

              Aliases::

                        addprinc ank

              The options are:

              **-x** *db_princ_args*
                     Denotes the database specific options. 

                     The options for LDAP database are:

                     **-x** dn=<dn>
                            Specifies the LDAP object that will contain the Kerberos principal being created.

                     **-x** linkdn=<dn>
                            Specifies the LDAP object to which the newly created Kerberos principal object will point to.

                     **-x** containerdn=<container_dn>
                            Specifies the container object under which the Kerberos principal is to be created.

                     **-x** tktpolicy=<policy>
                            Associates a ticket policy to the Kerberos principal.


                    .. note:: 
                            - *containerdn* and *linkdn* options cannot be specified with dn option.  
                            - If *dn* or *containerdn* options are not specified while adding the principal, the principals are created under the prinicipal container configured in the realm or the realm container. 
                            - *dn* and *containerdn* should be within the subtrees or principal container configured in the realm.


              **-expire** *expdate*
                     expiration date of the principal

              **-pwexpire** *pwexpdate*
                     password expiration date

              **-maxlife** *maxlife*
                     maximum ticket life for the principal

              **-maxrenewlife** *maxrenewlife*
                     maximum renewable life of tickets for the principal

              **-kvno** *kvno*
                     explicity set the key version number.

              **-policy** *policy*
                     policy used by this principal.  
                     If no policy is supplied, then if the policy "default" exists and the *-clearpolicy* is not also specified,  
                     then the policy "default" is used; 
                     otherwise, the principal will have no policy, and a warning message will be printed.

              **-clearpolicy**
                     *-clearpolicy* prevents the policy "default" from being assigned when *-policy* is not specified.  
                     This option has no effect if the policy "default" does not exist.

              {- | +} **allow_postdated**
                     *-allow_postdated* prohibits this principal from obtaining postdated tickets.
                     (Sets the *KRB5_KDB_DISALLOW_POSTDATED* flag.) *+allow_postdated* clears this flag.

              {- | +} **allow_forwardable**
                     *-allow_forwardable* prohibits this principal from obtaining forwardable tickets.  
                     (Sets the  *KRB5_KDB_DISALLOW_FORWARDABLE* flag.) 
                     *+allow_forwardable* clears this flag.

              {- | +} **allow_renewable**
                     *-allow_renewable* prohibits this principal from obtaining renewable tickets.  
                     (Sets the *KRB5_KDB_DISALLOW_RENEWABLE* flag.) 
                     *+allow_renewable* clears this flag.

              {- | +} **allow_proxiable**
                     *-allow_proxiable* prohibits this principal from obtaining proxiable tickets.  
                     (Sets the *KRB5_KDB_DISALLOW_PROXIABLE* flag.)
                     *+allow_proxiable* clears this flag.

              {- | +} **allow_dup_skey**
                     *-allow_dup_skey*  disables  user-to-user  authentication for this principal by prohibiting this principal from obtaining a
                     session key for another user.  
                     (Sets the *KRB5_KDB_DISALLOW_DUP_SKEY* flag.)  
                     *+allow_dup_skey* clears this flag.

              {- | +} **requires_preauth**
                     *+requires_preauth*  requires  this  principal  to  preauthenticate   before   being   allowed   to   kinit.    
                     (Sets   the *KRB5_KDB_REQUIRES_PRE_AUTH* flag.)  
                     *-requires_preauth* clears this flag.

              {- | +} **requires_hwauth**
                     *+requires_hwauth* requires this principal to preauthenticate using a hardware device before being allowed to kinit.  
                     (Sets the *KRB5_KDB_REQUIRES_HW_AUTH* flag.)  
                     *-requires_hwauth* clears this flag.

              {- | +} **ok_as_delegate**
                     *+ok_as_delegate* sets the OK-AS-DELEGATE flag on tickets issued for use with this principal as the service, 
                     which clients may use as a hint that credentials can and should be delegated when authenticating to the service.  
                     (Sets the *KRB5_KDB_OK_AS_DELEGATE* flag.)  
                     *-ok_as_delegate* clears this flag.

              {- | +} **allow_svr**
                     *-allow_svr* prohibits the issuance of service tickets for this principal.   
                     (Sets  the  *KRB5_KDB_DISALLOW_SVR*  flag.)
                     *+allow_svr* clears this flag.

              {- | +} **allow_tgs_req**
                     *-allow_tgs_req* specifies that a Ticket-Granting Service (TGS) request for a service ticket for this principal is not permitted.  
                     This option is useless for most things.  
                     *+allow_tgs_req* clears this flag.  
                     The default  is  +allow_tgs_req.   
                     In effect, *-allow_tgs_req sets* the *KRB5_KDB_DISALLOW_TGT_BASED* flag on the principal in the database.

              {- | +} **allow_tix**
                     *-allow_tix* forbids the issuance of any tickets for this principal.  
                     *+allow_tix* clears this flag.  
                     The default is *+allow_tix*.  In effect, *-allow_tix* sets the *KRB5_KDB_DISALLOW_ALL_TIX* flag on the principal in the database.

              {- | +} **needchange**
                     *+needchange* sets a flag in attributes field to force a password change; 
                     *-needchange* clears it.   
                     The  default  is  *-needchange*.  
                     In effect, *+needchange* sets the *KRB5_KDB_REQUIRES_PWCHANGE* flag on the principal in the database.

              {- | +} **password_changing_service**
                     *+password_changing_service*  sets a flag in the attributes field marking this as a password change service principal 
                     (useless for most things).  
                     *-password_changing_service* clears the flag.  This  flag  intentionally  has  a  long  name.   
                     The default  is *-password_changing_service*.  
                     In effect, *+password_changing_service* sets the *KRB5_KDB_PWCHANGE_SERVICE* flag on the principal in the database.

              **-randkey**
                     sets the key of the principal to a random value

              **-pw** *password*
                     sets the key of the principal to the specified string and does not prompt for a password.  Note:  using this option in  a
                     shell script can be dangerous if unauthorized users gain read access to the script.

              **-e** "enc:salt ..."
                     uses the specified list of enctype-salttype pairs for setting the key of the principal. The quotes are necessary if
                     there are multiple enctype-salttype pairs.  This will not function against *kadmin* daemons earlier than krb5-1.2.

              EXAMPLE::
  
                    kadmin: addprinc jennifer
                    WARNING: no policy specified for "jennifer@ATHENA.MIT.EDU";
                    defaulting to no policy.
                    Enter password for principal jennifer@ATHENA.MIT.EDU:  <= Type the password.
                    Re-enter password for principal jennifer@ATHENA.MIT.EDU:  <=Type it again.
                    Principal "jennifer@ATHENA.MIT.EDU" created.
                    kadmin:


              ERRORS::

                     KADM5_AUTH_ADD (requires "add" privilege)
                     KADM5_BAD_MASK (shouldn't happen)
                     KADM5_DUP (principal exists already)
                     KADM5_UNK_POLICY (policy does not exist)
                     KADM5_PASS_Q_* (password quality violations)

.. _add_principal_end:

.. _modify_principal:

modify_principal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **modify_principal** [options] *principal*
              Modifies the specified principal, changing the fields as specified. The options are as above for *add_principal*, except that
              password changing and flags related to password changing are forbidden by this command.  
              In addition, the option *-clearpolicy* will clear the current policy of a principal.  

                 .. note:: This command requires the *modify* privilege.  

              Alias:: 

                        modprinc

              The options are:

              **-x** *db_princ_args*
                     Denotes the database specific options. 

                     The options for LDAP database are:

                     **-x** tktpolicy=<policy>
                            Associates a ticket policy to the Kerberos principal.

                     **-x** linkdn=<dn>
                            Associates  a  Kerberos principal with a LDAP object. This option is honored only if the Kerberos principal is not
                            already associated with a LDAP object.

              **-unlock**
                     Unlocks a locked principal (one which has received too many failed authentication attempts without  enough  time  between
                     them according to its password policy) so that it can successfully authenticate.

              ERRORS::

                     KADM5_AUTH_MODIFY  (requires "modify" privilege) 
                     KADM5_UNK_PRINC (principal does not exist) 
                     KADM5_UNK_POLICY (policy does not exist) 
                     KADM5_BAD_MASK (shouldn't happen)

.. _modify_principal_end:

.. _delete_principal:

delete_principal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **delete_principal** [ *-force* ] *principal*
              Deletes the specified *principal* from the database.  This command prompts for deletion, unless the *-force* option is  given.  

                 .. note:: This command requires the *delete* privilege.  

              Alias:: 

                     delprinc


              ERRORS::

                     KADM5_AUTH_DELETE (reequires "delete" privilege)
                     KADM5_UNK_PRINC (principal does not exist)

.. _delete_principal_end:

.. _change_password:

change_password
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **change_password** [options] *principal*
              Changes the password of *principal*.  Prompts for a new password if neither *-randkey* or *-pw* is specified.  

                 .. note:: Requires  the  *changepw* privilege,  or that the principal that is running the program to be the same as the one changed.  

              Alias::

                      cpw

              The following options are available:

              **-randkey**
                     Sets the key of the principal to a random value

              **-pw** *password*
                     Set the password to the specified string.  Not recommended.

              **-e** "enc:salt ..."
                     Uses the specified list of enctype-salttype pairs for setting the key of the principal.   The quotes are necessary if
                     there are multiple enctype-salttype pairs.  This will not function against *kadmin* daemons earlier than krb5-1.2.
                     See :ref:`Supported_Encryption_Types_and_Salts` for possible values.

              **-keepold**
                     Keeps the previous kvno's keys around.  This flag is usually not necessary except perhaps for TGS keys.  Don't use this
                     flag unless you know what you're doing. This option is not supported for the LDAP database.

              EXAMPLE::

                     kadmin: cpw systest
                     Enter password for principal systest@BLEEP.COM:
                     Re-enter password for principal systest@BLEEP.COM:
                     Password for systest@BLEEP.COM changed.
                     kadmin:

              ERRORS::

                     KADM5_AUTH_MODIFY (requires the modify privilege)
                     KADM5_UNK_PRINC (principal does not exist)
                     KADM5_PASS_Q_* (password policy violation errors)
                     KADM5_PADD_REUSE (password is in principal's password
                     history)
                     KADM5_PASS_TOOSOON (current password minimum life not
                     expired)


.. _change_password_end:

.. _purgekeys:

purgekeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **purgekeys** [*-keepkvno oldest_kvno_to_keep* ] *principal*
              Purges previously retained old keys (e.g., from *change_password -keepold*) from *principal*.  
              If **-keepkvno** is specified, then only purges keys with kvnos lower than *oldest_kvno_to_keep*.

.. _purgekeys_end:

.. _get_principal:

get_principal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **get_principal** [*-terse*] *principal*
              Gets  the  attributes of principal.  
              With the **-terse** option, outputs fields as quoted tab-separated strings.  
 
                 .. note:: Requires the *inquire* privilege, or that the principal that is running the the program to be the same as the one being listed.  

              Alias::

                     getprinc


              EXAMPLES::

                     kadmin: getprinc tlyu/admin
                     Principal: tlyu/admin@BLEEP.COM
                     Expiration date: [never]
                     Last password change: Mon Aug 12 14:16:47 EDT 1996
                     Password expiration date: [none]
                     Maximum ticket life: 0 days 10:00:00
                     Maximum renewable life: 7 days 00:00:00
                     Last modified: Mon Aug 12 14:16:47 EDT 1996 (bjaspan/admin@BLEEP.COM)
                     Last successful authentication: [never]
                     Last failed authentication: [never]
                     Failed password attempts: 0
                     Number of keys: 2
                     Key: vno 1, DES cbc mode with CRC-32, no salt
                     Key: vno 1, DES cbc mode with CRC-32, Version 4
                     Attributes:
                     Policy: [none]


                     kadmin: getprinc -terse systest
                     systest@BLEEP.COM   3    86400     604800    1
                     785926535 753241234 785900000
                     tlyu/admin@BLEEP.COM     786100034 0    0
                     kadmin:


              ERRORS::

                     KADM5_AUTH_GET (requires the get (inquire) privilege)
                     KADM5_UNK_PRINC (principal does not exist)

.. _get_principal_end:

.. _list_principals:

list_principals
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **list_principals** [expression]
              Retrieves all or some principal names.  
              Expression is a shell-style glob expression that can contain the wild-card characters ?, \*,  and  []'s.  
              All principal names matching the expression are printed.
              If no expression is provided, all principal names are printed.  
              If the expression does not contain an "@" character, an "@" character followed by the local realm is appended  to  the expression.  
              
                 .. note:: Requires the *list* priviledge.  

              Aliases::
                
                       listprincs get_principals get_princs 

              EXAMPLES::
 
                     kadmin:  listprincs test* 
                     test3@SECURE-TEST.OV.COM
                     test2@SECURE-TEST.OV.COM
                     test1@SECURE-TEST.OV.COM
                     testuser@SECURE-TEST.OV.COM
                     kadmin:

.. _list_principals_end:

.. _get_strings:

get_strings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **get_strings** *principal*
              Displays string attributes on *principal*.
	      String attributes are used to supply per-principal configuration to some KDC plugin modules.

              Alias::

                     getstr

.. _set_string:

set_string
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **set_string** *principal* *key* *value*
              Sets a string attribute on *principal*.

              Alias::

                     setstr

.. _del_string:

del_string
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **del_string** *principal* *key*
              Deletes a string attribute from *principal*.

              Alias::

                     delstr

.. _add_policy:

add_policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **add_policy** [options] *policy*
              Adds the named *policy* to the policy database.  

                 .. note:: Requires the *add* privilege.  

              Alias::

                        addpol

              The following options are available:

              **-maxlife time**
                     sets the maximum lifetime of a password

              **-minlife time**
                     sets the minimum lifetime of a password

              **-minlength length**
                     sets the minimum length of a password

              **-minclasses number**
                     sets the minimum number of character classes allowed in a password

              **-history number**
                     sets the number of past keys kept for a principal. This option is not supported for LDAP database

              **-maxfailure maxnumber**
                     sets the maximum number of authentication failures before the principal is  locked.
                     Authentication failures are only tracked for principals which require preauthentication.

              **-failurecountinterval failuretime**
                     sets  the  allowable  time  between  authentication failures.  
                     If an authentication failure happens after *failuretime* has elapsed since the previous failure, 
                     the number of authentication failures is reset to 1.

              **-lockoutduration lockouttime**
                     sets the duration for which the principal is locked from authenticating if too many authentication failures occur without
                     the specified failure count interval elapsing.


              EXAMPLES::

                     kadmin: add_policy -maxlife "2 days" -minlength 5 guests
                     kadmin:

              ERRORS::

                     KADM5_AUTH_ADD (requires the add privilege)
                     KADM5_DUP (policy already exists)

.. _add_policy_end:

.. _modify_policy:

modify_policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **modify_policy** [options] *policy*
              modifies the named *policy*.  Options are as above for *add_policy*.  

                 .. note:: Requires the *modify* privilege.  

              Alias::

                      modpol


              ERRORS::

                     KADM5_AUTH_MODIFY (requires the modify privilege)
                     KADM5_UNK_POLICY (policy does not exist)

.. _modify_policy_end:

.. _delete_policy:

delete_policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **delete_policy** [ *-force* ] *policy*
              deletes the named *policy*.  Prompts for confirmation before deletion.  
              The command will fail if the policy is in use by any principals.  

                 .. note:: Requires the *delete* privilege.  

              Alias::

                      delpol


              EXAMPLE::

                     kadmin: del_policy guests
                     Are you sure you want to delete the policy "guests"?
                     (yes/no): yes
                     kadmin:

              ERRORS::

                     KADM5_AUTH_DELETE (requires the delete privilege)
                     KADM5_UNK_POLICY (policy does not exist)
                     KADM5_POLICY_REF (reference count on policy is not zero)

.. _delete_policy_end:

.. _get_policy:

get_policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **get_policy** [ **-terse** ] *policy*
              displays the values of the named *policy*.  
              With the **-terse** flag, outputs the fields as quoted strings separated by tabs.  

                 .. note:: Requires the *inquire* privilege.  


              Alias::

                       getpol


              EXAMPLES::

                     kadmin: get_policy admin
                     Policy: admin
                     Maximum password life: 180 days 00:00:00
                     Minimum password life: 00:00:00
                     Minimum password length: 6
                     Minimum number of password character classes: 2
                     Number of old keys kept: 5
                     Reference count: 17

                     kadmin: get_policy -terse admin
                     admin     15552000  0    6    2    5    17
                     kadmin:

              The *Reference count* is the number of principals using that policy.

              ERRORS::

                     KADM5_AUTH_GET (requires the get privilege)
                     KADM5_UNK_POLICY (policy does not exist)

.. _get_policy_end:

.. _list_policies:

list_policies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **list_policies** [expression]
              Retrieves all or some policy names.  Expression is a shell-style glob expression that can contain the wild-card characters ?, \*, and []'s.  
              All policy names matching the expression are printed.  
              If no expression is provided, all existing policy names are printed.  

                 .. note:: Requires the *list* priviledge.  

              Alias::

                      listpols, get_policies, getpols.


              EXAMPLES::

                     kadmin:  listpols
                     test-pol
                     dict-only
                     once-a-min
                     test-pol-nopw

                     kadmin:  listpols t*
                     test-pol
                     test-pol-nopw
                     kadmin:

.. _list_policies_end:

.. _ktadd:

ktadd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **ktadd**  [[*principal* | **-glob** *princ-exp*]
              Adds a *principal* or all principals matching *princ-exp* to a keytab file.  
              It randomizes each principal's key in the process, to prevent a compromised admin account from reading out all of the keys from the database.  
              The rules for principal expression are the same as for the *kadmin* :ref:`list_principals` command. 

                 .. note:: Requires the  *inquire* and *changepw* privileges.  
                           
                           If you use the *-glob* option, it also requires the *list* administrative privilege. 

              The options are:

              **-k[eytab]**  *keytab*  
                     Use *keytab* as the keytab file. Otherwise, *ktadd* will use the default keytab file (*/etc/krb5.keytab*).

              **-e** *"enc:salt..."*
                     Use the specified list of enctype-salttype pairs for setting the key of the principal. 
                     The enctype-salttype pairs may be delimited with commas or whitespace.
                     The quotes are necessary for whitespace-delimited list.
                     If this option is not specified, then *supported_enctypes* from :ref:`krb5.conf` will be used.
                     See :ref:`Supported_Encryption_Types_and_Salts` for all possible values.

              **-q**
                     Run in quiet mode. This causes *ktadd* to display less verbose information.

              **-norandkey**
                     Do not randomize the keys. The keys and their version numbers stay unchanged.
                     That allows users to continue to use the passwords they know to login normally, 
                     while simultaneously allowing scripts to login to the same account using a *keytab*.  
                     There is no significant security risk added since *kadmin.local* must be run by root on the KDC anyway.
                     This option is only available in *kadmin.local* and cannot be specified in combination with *-e* option.


              .. note:: An entry for each of the principal's unique encryption types is added, ignoring multiple keys with the same encryption type but different salt types.


              EXAMPLE::

                     kadmin: ktadd -k /tmp/foo-new-keytab host/foo.mit.edu
                     Entry for principal host/foo.mit.edu@ATHENA.MIT.EDU with
                          kvno 3, encryption type DES-CBC-CRC added to keytab
                          WRFILE:/tmp/foo-new-keytab
                     kadmin:

.. _ktadd_end:

.. _ktremove:

ktremove
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

       **ktremove**  *principal* [*kvno* | *all* | *old*]
              Removes entries for the specified *principal* from a keytab.  Requires no permissions, since this does not require database access. 


              If the string "all" is specified, all entries for that principal are removed; 
              if the string "old" is specified, all entries for that principal except those with the highest kvno are removed.  
              Otherwise, the value specified is parsed as an integer, and all entries whose *kvno* match that integer are removed.

              The options are:

              **-k[eytab]**  *keytab*  
                     Use keytab as the keytab file. Otherwise, *ktremove* will use the default keytab file (*/etc/krb5.keytab*).

              **-q**
                     Run in quiet mode. This causes *ktremove* to display less verbose information.

              EXAMPLE::

                     kadmin: ktremove -k /usr/local/var/krb5kdc/kadmind.keytab kadmin/admin all
                     Entry for principal kadmin/admin with kvno 3 removed
                          from keytab WRFILE:/usr/local/var/krb5kdc/kadmind.keytab.
                     kadmin:

.. _ktremove_end:


FILES
-----------

.. note::  The first three files are specific to db2 database.

====================== =================================================
principal.db            default name for Kerberos principal database
<dbname>.kadm5          KADM5 administrative database. (This would be "principal.kadm5", if you use the default database name.)  Contains policy information.
<dbname>.kadm5.lock     Lock file for the KADM5 administrative database.  This file works backwards from most other lock files. I.e., *kadmin* will exit with an error if this file does not exist.
kadm5.acl               File containing list of principals and their *kadmin* administrative privileges.  See kadmind(8) for a description.
kadm5.keytab            *keytab* file for *kadmin/admin* principal.
kadm5.dict              file containing dictionary of strings explicitly disallowed as passwords.
====================== =================================================



HISTORY
-------------

The *kadmin* prorgam was originally written by Tom Yu at MIT, as an interface to the OpenVision Kerberos administration program.


SEE ALSO
------------

kerberos(1), kpasswd(1), kadmind(8)


