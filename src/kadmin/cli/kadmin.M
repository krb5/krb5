.TH KADMIN 1
.SH NAME
kadmin \- Kerberos V5 database administration program
.SH SYNOPSYS
.TP
.B kadmin
.ad l
[\fB\-O\fP | \fB\-N\fP]
[\fB\-r\fP \fIrealm\fP] [\fB\-p\fP \fIprincipal\fP] [\fB\-q\fP \fIquery\fP]
.br
[[\fB-c\fP \fIcache_name\fP] | [\fB-k\fP [\fB-t\fP
\fIkeytab\fP]] | \fB-n\fP] [\fB\-w\fP \fIpassword\fP] [\fB\-s\fP
\fIadmin_server\fP[\fI:port\fP]
.TP "\w'.B kadmin.local\ 'u"
.B kadmin.local
[\fB\-r\fP \fIrealm\fP] [\fB\-p\fP \fIprincipal\fP] [\fB\-q\fP \fIquery\fP]
.br
[\fB\-d\fP \fIdbname\fP] [\fB\-e \fI"enc:salt ..."\fP] [\fB-m\fP] [\fB\-x\fP \fIdb_args\fP]
.ad b
.SH DESCRIPTION
.B kadmin
and
.B kadmin.local
are command-line interfaces to the Kerberos V5 KADM5 administration
system.  Both
.B kadmin
and
.B kadmin.local
provide identical functionalities; the difference is that
.B kadmin.local
runs on the master KDC if the database is db2 and
does not use Kerberos to authenticate to the
database. Except as explicitly noted otherwise, 
this man page will use
.B kadmin
to refer to both versions.
.B kadmin
provides for the maintenance of Kerberos principals, KADM5 policies, and
service key tables (keytabs).  
.PP
The remote version uses Kerberos authentication and an encrypted RPC, to
operate securely from anywhere on the network.  It authenticates to the
KADM5 server using the service principal
.IR kadmin/admin .
If the credentials cache contains a ticket for the
.I kadmin/admin
principal, and the 
.B \-c
.I credentials_cache
option is specified, that ticket is used to authenticate to KADM5.
Otherwise, the
.B -p
and
.B -k
options are used to specify the client Kerberos principal name used to
authenticate.  Once
.B kadmin
has determined the principal name, it requests a
.I kadmin/admin
Kerberos service ticket from the KDC, and uses that service ticket to
authenticate to KADM5.
.PP
If the database is db2, the local client
.BR kadmin.local ,
is intended to run directly on the master KDC without Kerberos
authentication.  The local version provides all of the functionality of
the now obsolete
.IR kdb5_edit (8),
except for database dump and load, which is now provided by the
.IR kdb5_util (8)
utility.
.PP
If the database is LDAP, kadmin.local need not be run on the KDC. 
.PP
kadmin.local can be configured to log updates for incremental database
propagation.  Incremental propagation allows slave KDC servers to
receive principal and policy updates incrementally instead of
receiving full dumps of the database.  This facility can be enabled in
the
.I kdc.conf
file with the
.I iprop_enable
option.  See the
.I kdc.conf
documentation for other options for tuning incremental propagation
parameters.

.SH OPTIONS
.TP
\fB\-r\fP \fIrealm\fP
Use
.I realm
as the default database realm.
.TP
\fB\-p\fP \fIprincipal\fP
Use
.I principal
to authenticate.  Otherwise, kadmin will append "/admin" to the primary
principal name of the default ccache, the value of the
.SM USER
environment variable, or the username as obtained with getpwuid, in
order of preference.
.TP
\fB\-k\fP
Use a keytab to decrypt the KDC response instead of prompting for a
password on the TTY.  In this case, the default principal will be
host/\fIhostname\fP.  If there is not a keytab specified with the
.B \-t
option, then the default keytab will be used.
.TP
\fB\-t\fP \fIkeytab\fP
Use
.I keytab
to decrypt the KDC response.  This can only be used with the
.B \-k
option.
\fB-n\fP
Requests anonymous processing.  Two types of anonymous principals are
supported.  For fully anonymous Kerberos, configure pkinit on the KDC
and configure
.I pkinit_anchors
in the client's krb5.conf.  Then use the
.B -n
option with a principal of the form
.I @REALM
(an empty principal name followed by the at-sign and a realm name).
If permitted by the KDC, an anonymous ticket will be returned.
A second form of anonymous tickets is supported; these realm-exposed
tickets hide the identity of the client but not the client's realm.
For this mode, use
.B kinit -n
with a normal principal name.  If supported by the KDC, the principal
(but not realm) will be replaced by the anonymous principal.
As of release 1.8, the MIT Kerberos KDC only supports fully anonymous
operation.
.TP
\fB\-c\fP \fIcredentials_cache\fP
Use
.I credentials_cache
as the credentials cache.  The
.I credentials_cache
should contain a service ticket for the
.I kadmin/admin
service; it can be acquired with the
.IR kinit (1)
program.  If this option is not specified,
.B kadmin
requests a new service ticket from the KDC, and stores it in its own
temporary ccache.
.TP
\fB\-w\fP \fIpassword\fP
Use
.I password
instead of prompting for one on the TTY.  Note:  placing the password
for a Kerberos principal with administration access into a shell script
can be dangerous if unauthorized users gain read access to the script.
.TP
\fB\-q\fP \fIquery\fP
pass
.I query
directly to
.BR kadmin ,
which will perform
.I query
and then exit.  This can be useful for writing scripts.
.TP
\fB\-d\fP \fIdbname\fP
Specifies the name of the Kerberos database.
This option does not apply to the LDAP database.
.TP
\fB\-s\fP \fIadmin_server[:port]\fP
Specifies the admin server which kadmin should contact.
.TP
\fB\-m\fP
Do not authenticate using a keytab.  This option will cause kadmin
to prompt for the master database password.
.TP
\fB\-e\fP \fIenc:salt_list\fP
Sets the list of encryption types and salt types to be used for any new
keys created.
.TP
.B \-O
Force use of old AUTH_GSSAPI authentication flavor.
.TP
.B \-N
Prevent fallback to AUTH_GSSAPI authentication flavor.
.TP
\fB\-x\fP \fIdb_args\fP
Specifies the database specific arguments.

Options supported for LDAP database are:
.RS
.TP
\-x host=<hostname>
specifies the LDAP server to connect to by a LDAP URI.
.TP
\-x binddn=<bind_dn>
.fi
specifies the DN of the object used by the administration server to bind to the LDAP server.
This object should have the read and write rights on the realm container, principal container
and the subtree that is referenced by the realm.
.TP
\-x bindpwd=<bind_password>
.fi
specifies the password for the above mentioned binddn. It is recommended not to use this option.
Instead, the password can be stashed using the stashsrvpw command of kdb5_ldap_util.
.RE
.SH DATE FORMAT 
Various commands in kadmin can take a variety of date formats,
specifying durations or absolute times.  Examples of valid formats are:
.sp
.nf
.RS
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
a fortnight ago
3/31/92 10:00:07 PST
January 23, 1987 10:05pm
22:00 GMT
.RE
.fi
.PP
Dates which do not have the "ago" specifier default to being absolute
dates, unless they appear in a field where a duration is expected.  In
that case the time specifier will be interpreted as relative.
Specifying "ago" in a duration may result in unexpected behavior.
.PP
.SH COMMANDS
.TP
\fBadd_principal\fP [\fIoptions\fP] \fInewprinc\fP
creates the principal
.IR newprinc ,
prompting twice for a password.  If no policy is specified with the
\-policy option, and the policy named "default" exists, then that
policy is assigned to the principal; note that the assignment of the
policy "default" only occurs automatically when a principal is first
created, so the policy "default" must already exist for the assignment
to occur.  This assignment of "default" can be suppressed with the
\-clearpolicy option.  This command requires the 
.I add
privilege.  This command has the aliases
.B addprinc
and
.BR ank .
The options are:
.RS
.TP
\fB\-x\fP \fIdb_princ_args\fP
Denotes the database specific options. The options for LDAP database are:
.RS
.TP
\-x dn=<dn>
Specifies the LDAP object that will contain the Kerberos principal being 
created.
.TP
\-x linkdn=<dn>
.fi
Specifies the LDAP object to which the newly created Kerberos principal object
will point to.
.TP
\-x containerdn=<container_dn>
Specifies the container object under which the Kerberos principal is to be created. 
.TP
\-x tktpolicy=<policy>
Associates a ticket policy to the Kerberos principal.
.RE
.TP
\fB\-expire\fP \fIexpdate\fP
expiration date of the principal
.TP
\fB\-pwexpire\fP \fIpwexpdate\fP
password expiration date
.TP
\fB\-maxlife\fP \fImaxlife\fP
maximum ticket life for the principal
.TP
\fB\-maxrenewlife\fP \fImaxrenewlife\fP
maximum renewable life of tickets for the principal
.TP
\fB\-kvno\fP \fIkvno\fP
explicity set the key version number.
.TP
\fB\-policy\fP \fIpolicy\fP
policy used by this principal.  If no policy is supplied, then if the
policy "default" exists and the -clearpolicy is not also specified,
then the policy "default" is used; otherwise, the principal 
will have no policy, and a warning message will be printed.
.TP
\fB\-clearpolicy\fP 
.B -clearpolicy
prevents the policy "default" from being assigned when 
.B -policy
is not specified.  This option has no effect if the policy "default"
does not exist.
.TP
{\fB\-\fP|\fB+\fP}\fBallow_postdated\fP
.B -allow_postdated
prohibits this principal from obtaining postdated tickets.  (Sets the
.SM KRB5_KDB_DISALLOW_POSTDATED
flag.)
.B +allow_postdated
clears this flag.
.TP
{\fB\-\fP|\fB+\fP}\fBallow_forwardable\fP
.B -allow_forwardable
prohibits this principal from obtaining forwardable tickets.  (Sets the
.SM KRB5_KDB_DISALLOW_FORWARDABLE
flag.)
.B +allow_forwardable
clears this flag.
.TP
{\fB\-\fP|\fB+\fP}\fBallow_renewable\fP
.B -allow_renewable
prohibits this principal from obtaining renewable tickets.  (Sets the
.SM KRB5_KDB_DISALLOW_RENEWABLE
flag.)
.B +allow_renewable
clears this flag.
.TP
{\fB\-\fP|\fB+\fP}\fBallow_proxiable\fP
.B -allow_proxiable
prohibits this principal from obtaining proxiable tickets.  (Sets the
.SM KRB5_KDB_DISALLOW_PROXIABLE
flag.)
.B +allow_proxiable
clears this flag.
.TP
{\fB\-\fP|\fB+\fP}\fBallow_dup_skey\fP
.B -allow_dup_skey
Disables user-to-user authentication for this principal by prohibiting
this principal from obtaining a session key for another user.  (Sets the
.SM KRB5_KDB_DISALLOW_DUP_SKEY
flag.)
.B +allow_dup_skey
clears this flag.
.TP
{\fB\-\fP|\fB+\fP}\fBrequires_preauth\fP
.B +requires_preauth
requires this principal to preauthenticate before being allowed to
kinit.  (Sets the
.SM KRB5_KDB_REQUIRES_PRE_AUTH
flag.)
.B -requires_preauth
clears this flag.
.TP
{\fB\-\fP|\fB+\fP}\fBrequires_hwauth\fP
.B +requires_hwauth
requires this principal to preauthenticate using a hardware device
before being allowed to kinit.  (Sets the
.SM KRB5_KDB_REQUIRES_HW_AUTH
flag.)
.B -requires_hwauth
clears this flag.
.TP
{\fB\-\fP|\fB+\fP}\fBok_as_delegate\fP
.B +ok_as_delegate
sets the OK-AS-DELEGATE flag on tickets issued for use with this principal
as the service, which clients may use as a hint that credentials can and
should be delegated when authenticating to the service.  (Sets the
.SM KRB5_KDB_OK_AS_DELEGATE
flag.)
.B -ok_as_delegate
clears this flag.
.TP
{\fB\-\fP|\fB+\fP}\fBallow_svr\fP
.B -allow_svr
prohibits the issuance of service tickets for this principal.  (Sets the
.SM KRB5_KDB_DISALLOW_SVR
flag.)
.B +allow_svr
clears this flag.
.TP
{\fB\-\fP|\fB+\fP}\fBallow_tgs_req\fP
.B \-allow_tgs_req
specifies that a Ticket-Granting Service (TGS) request for a service
ticket for this principal is not permitted.  This option is useless for
most things.
.B +allow_tgs_req
clears this flag.  The default is
.BR +allow_tgs_req .
In effect,
.B \-allow_tgs_req
sets the
.SM KRB5_KDB_DISALLOW_TGT_BASED
flag on the principal in the database.
.TP
{\fB\-\fP|\fB+\fP}\fBallow_tix\fP
.B \-allow_tix
forbids the issuance of any tickets for this principal.
.B +allow_tix
clears this flag.  The default is
.BR +allow_tix .
In effect,
.B \-allow_tix
sets the
.SM KRB5_KDB_DISALLOW_ALL_TIX
flag on the principal in the database.
.TP
{\fB\-\fP|\fB+\fP}\fBneedchange\fP
.B +needchange
sets a flag in attributes field to force a password change;
.B \-needchange
clears it.  The default is
.BR \-needchange .
In effect,
.B +needchange
sets the
.SM KRB5_KDB_REQUIRES_PWCHANGE
flag on the principal in the database.
.TP
{\fB\-\fP|\fB+\fP}\fBpassword_changing_service\fP
.B +password_changing_service
sets a flag in the attributes field marking this as a password change
service principal (useless for most things).
.B \-password_changing_service
clears the flag.  This flag intentionally has a long name.  The default
is
.BR \-password_changing_service .
In effect,
.B +password_changing_service
sets the
.SM KRB5_KDB_PWCHANGE_SERVICE
flag on the principal in the database.
.TP
.B \-randkey
sets the key of the principal to a random value
.TP
\fB\-pw\fP \fIpassword\fP
sets the key of the principal to the specified string and does not
prompt for a password.  Note:  using this option in a shell script can
be dangerous if unauthorized users gain read access to the script.
.TP
\fB\-e\fP \fI"enc:salt ..."\fP
uses the specified list of enctype\-salttype pairs for setting the key
of the principal.  The quotes are necessary if there are multiple
enctype\-salttype pairs.  This will not function against kadmin
daemons earlier than krb5\-1.2.
.nf
.TP
EXAMPLE:
kadmin: addprinc tlyu/admin
WARNING: no policy specified for "tlyu/admin@BLEEP.COM";
defaulting to no policy.
Enter password for principal tlyu/admin@BLEEP.COM:
Re-enter password for principal tlyu/admin@BLEEP.COM:
Principal "tlyu/admin@BLEEP.COM" created.
kadmin:

kadmin: addprinc \-x dn=cn=mwm_user,o=org mwm_user
WARNING: no policy specified for "mwm_user@BLEEP.COM";
defaulting to no policy.
Enter password for principal mwm_user@BLEEP.COM: 
Re-enter password for principal mwm_user@BLEEP.COM: 
Principal "mwm_user@BLEEP.COM" created.
kadmin:

.TP
ERRORS:
KADM5_AUTH_ADD (requires "add" privilege)
KADM5_BAD_MASK (shouldn't happen)
KADM5_DUP (principal exists already)
KADM5_UNK_POLICY (policy does not exist)
KADM5_PASS_Q_* (password quality violations)
.fi
.RE
.TP
\fBdelete_principal\fP [\fB-force\fP] \fIprincipal\fP
deletes the specified principal from the database.  This command prompts
for deletion, unless the
.B -force
option is given. This command requires the
.I delete
privilege.  Aliased
to
.BR delprinc.
.sp
.nf
.RS
.TP
EXAMPLE:
kadmin: delprinc mwm_user
Are you sure you want to delete the principal
"mwm_user@BLEEP.COM"? (yes/no): yes
Principal "mwm_user@BLEEP.COM" deleted.
Make sure that you have removed this principal from
all ACLs before reusing.
kadmin:
.TP
ERRORS:
KADM5_AUTH_DELETE (reequires "delete" privilege)
KADM5_UNK_PRINC (principal does not exist)
.RE
.fi
.TP
\fBmodify_principal\fP [\fIoptions\fP] \fIprincipal\fP
modifies the specified principal, changing the fields as specified.  The
options are as above for
.BR add_principal ,
except that password changing and flags related to password changing
are forbidden by this command.  In addition, the option
.B \-clearpolicy
will clear the current policy of a principal.  This command requires the
.I modify
privilege.  Aliased to
.BR modprinc .
.RS
.TP
\fB\-x\fP \fIdb_princ_args\fP
Denotes the database specific options. The options for LDAP database are:
.RS
.TP
\-x tktpolicy=<policy>
Associates a ticket policy to the Kerberos principal.
.TP
\-x linkdn=<dn>
.fi
Associates a Kerberos principal with a LDAP object. This option is honored only
if the Kerberos principal is not already associated with a LDAP object. 
.RE
.TP
ERRORS:
KADM5_AUTH_MODIFY (requires "modify" privilege)
KADM5_UNK_PRINC (principal does not exist)
KADM5_UNK_POLICY (policy does not exist)
KADM5_BAD_MASK (shouldn't happen)
.RE
.fi
.TP
\fBchange_password\fP [\fIoptions\fP] \fIprincipal\fP
changes the password of
.IR principal .
Prompts for a new password if neither
.B \-randkey
or
.B \-pw
is specified.  Requires the
.I changepw
privilege, or that the principal that is running the program to be the
same as the one changed.  Aliased to
.BR cpw .
The following options are available:
.RS
.TP
.B \-randkey
sets the key of the principal to a random value
.TP
\fB\-pw\fP \fIpassword\fP
set the password to the specified string.  Not recommended.
.TP
\fB\-e\fP \fI"enc:salt ..."\fP
uses the specified list of enctype\-salttype pairs for setting the key
of the principal.  The quotes are necessary if there are multiple
enctype\-salttype pairs.  This will not function against kadmin
daemons earlier than krb5\-1.2.
.TP
\fB\-keepold \fP 
Keeps the previous kvno's keys around.  This flag is usually not
necessary except perhaps for TGS keys.  Don't use this flag unless you
know what you're doing. This option is not supported for the LDAP database.
.nf
.TP
EXAMPLE:
kadmin: cpw systest
Enter password for principal systest@BLEEP.COM:
Re-enter password for principal systest@BLEEP.COM:
Password for systest@BLEEP.COM changed.
kadmin:
.TP
ERRORS:
KADM5_AUTH_MODIFY (requires the modify privilege)
KADM5_UNK_PRINC (principal does not exist)
KADM5_PASS_Q_* (password policy violation errors)
KADM5_PADD_REUSE (password is in principal's password
history)
KADM5_PASS_TOOSOON (current password minimum life not
expired)
.RE
.fi
.TP
\fBpurgekeys\fP [\fB-keepkvno\fP \fIoldest_kvno_to_keep\fP] \fIprincipal\fP
purges previously retained old keys (e.g., from
.B change_password
.BR -keepold )
from
.IR principal .
If
.B -keepkvno
is specified, then only purges keys with kvnos lower than
.IR oldest_kvno_to_keep .
.fi
.TP
\fBget_principal\fP [\fB-terse\fP] \fIprincipal\fP
gets the attributes of
.IR principal .
Requires the
.I inquire
privilege, or that the principal that is running the the program to be
the same as the one being listed.  With the
.B \-terse
option, outputs fields as quoted tab-separated strings.  Alias
.BR getprinc .
.sp
.nf
.RS
.TP
EXAMPLES:
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
systest@BLEEP.COM	3	86400	604800	1
785926535	753241234	785900000
tlyu/admin@BLEEP.COM	786100034	0	0
kadmin:
.TP
ERRORS:
KADM5_AUTH_GET (requires the get (inquire) privilege)
KADM5_UNK_PRINC (principal does not exist)
.RE
.fi
.TP
\fBlist_principals\fP [\fIexpression\fP]
Retrieves all or some principal names.  
.I Expression
is a shell-style glob expression that can contain the wild-card
characters \&?, *, and []'s.  All principal names matching the
expression are printed.  If no expression is provided, all principal
names are printed.  If the expression does not contain an "@" character,
an "@" character followed by the local realm is appended to the
expression.  Requires the
.I list
priviledge.  Alias
.BR listprincs ,
.BR get_principals ,
.BR get_princs .
.nf
.RS
.TP
EXAMPLES:
kadmin:  listprincs test*
test3@SECURE-TEST.OV.COM
test2@SECURE-TEST.OV.COM
test1@SECURE-TEST.OV.COM
testuser@SECURE-TEST.OV.COM
kadmin:
.RE
.fi
.TP
\fBadd_policy\fP [\fIoptions\fP] \fIpolicy\fP
adds the named policy to the policy database.  Requires the
.I add
privilege.  Aliased to
.BR addpol .
The following options are available:
.RS
.TP
\fB\-maxlife\fP \fItime\fP
sets the maximum lifetime of a password
.TP
\fB\-minlife\fP \fItime\fP
sets the minimum lifetime of a password
.TP
\fB\-minlength\fP \fIlength\fP
sets the minimum length of a password
.TP
\fB\-minclasses\fP \fInumber\fP
sets the minimum number of character classes allowed in a password
.TP
\fB\-history\fP \fInumber\fP
sets the number of past keys kept for a principal. This option is not supported for LDAP database
.sp
.nf
.TP
EXAMPLES:
kadmin: add_policy \-maxlife "2 days" \-minlength 5 guests
kadmin:
.TP
ERRORS:
KADM5_AUTH_ADD (requires the add privilege)
KADM5_DUP (policy already exists)
.fi
.RE
.TP
\fBdelete_policy [\-force]\fP \fIpolicy\fB
deletes the named policy.  Prompts for confirmation before deletion.
The command will fail if the policy is in use by any principals.
Requires the
.I delete
privilege.  Alias
.BR delpol .
.sp
.nf
.RS
.TP
EXAMPLE:
kadmin: del_policy guests
Are you sure you want to delete the policy "guests"?
(yes/no): yes
kadmin:
.TP
ERRORS:
KADM5_AUTH_DELETE (requires the delete privilege)
KADM5_UNK_POLICY (policy does not exist)
KADM5_POLICY_REF (reference count on policy is not zero)
.RE
.fi
.TP
\fBmodify_policy\fP [\fIoptions\fP] \fIpolicy\fP
modifies the named policy.  Options are as above for
.BR add_policy .
Requires the
.I modify
privilege.  Alias
.BR modpol .
.sp
.nf
.RS
.TP
ERRORS:
KADM5_AUTH_MODIFY (requires the modify privilege)
KADM5_UNK_POLICY (policy does not exist)
.RE
.fi
.TP
\fBget_policy\fP [\fB\-terse\fP] \fIpolicy\fP
displays the values of the named policy.  Requires the
.I inquire
privilege.  With the
.B \-terse
flag, outputs the fields as quoted strings separated by tabs.  Alias
.BR getpol .
.nf
.RS
.TP
EXAMPLES:
kadmin: get_policy admin
Policy: admin
Maximum password life: 180 days 00:00:00
Minimum password life: 00:00:00
Minimum password length: 6
Minimum number of password character classes: 2
Number of old keys kept: 5
Reference count: 17
kadmin: get_policy -terse admin
admin	15552000	0	6	2	5	17
kadmin:
.TP
ERRORS:
KADM5_AUTH_GET (requires the get privilege)
KADM5_UNK_POLICY (policy does not exist)
.RE
.fi
.TP
\fBlist_policies\fP [\fIexpression\fP]
Retrieves all or some policy names.  
.I Expression
is a shell-style glob expression that can contain the wild-card
characters \&?, *, and []'s.  All policy names matching the expression
are printed.  If no expression is provided, all existing policy names
are printed.  Requires the
.I list
priviledge.  Alias
.BR listpols ,
.BR get_policies ,
.BR getpols .
.sp
.nf
.RS
.TP
EXAMPLES:
kadmin:  listpols
test-pol
dict-only
once-a-min
test-pol-nopw
kadmin:  listpols t*
test-pol
test-pol-nopw
kadmin:
.RE
.fi
.TP
\fBktadd\fP [\fB\-k\fP \fIkeytab\fP] [\fB\-q\fP] [\fB\-e\fP \fIkeysaltlist\fP]
.br
[\fB\-norandkey\fP] [[\fIprincipal\fP | \fB\-glob\fP \fIprinc-exp\fP] [\fI...\fP]
.br
Adds a principal or all principals matching
.I princ-exp
to a keytab.
It randomizes each principal's key in the process, to prevent a
compromised admin account from reading out all of the keys from the
database.  However,
.B kadmin.local
has the
.B \-norandkey
option, which leaves the keys and their version numbers unchanged,
similar to the Kerberos V4
.B ext_srvtab
command.
That allows users to continue to use the passwords they know
to login normally, while simultaneously allowing scripts
to login to the same account using a keytab.
There is no significant security risk added since
.B kadmin.local
must be run by root on the KDC anyway.
.sp
Requires the
.I inquire
and 
.I changepw
privileges.  An entry for each of the principal's unique encryption types
is added, ignoring multiple keys with the same encryption type but
different salt types.  If the
.B \-k
argument is not specified, the default keytab
.I /etc/krb5.keytab
is used.  If the
.B \-q
option is specified, less verbose status information is displayed.
.sp
The
.B -glob
option requires the
.I list
privilege.
.I princ-exp
follows the same rules described for the
.B list_principals
command.  
.sp
.nf
.RS
.TP
EXAMPLE:
kadmin: ktadd -k /tmp/foo-new-keytab host/foo.mit.edu
Entry for principal host/foo.mit.edu@ATHENA.MIT.EDU with
	kvno 3, encryption type DES-CBC-CRC added to keytab
	WRFILE:/tmp/foo-new-keytab
kadmin:
.RE
.fi
.TP
\fBktremove\fP [\fB\-k\fP \fIkeytab\fP] [\fB\-q\fP] \fIprincipal\fP [\fIkvno\fP | \fBall\fP | \fBold\fP]
Removes entries for the specified principal from a keytab.  Requires no
permissions, since this does not require database access.  If the string
"all" is specified, all entries for that principal are removed; if the
string "old" is specified, all entries for that principal except those
with the highest kvno are removed.  Otherwise, the value specified is
parsed as an integer, and all entries whose kvno match that integer are
removed.  If the
.B \-k
argument is not specifeid, the default keytab
.I /etc/krb5.keytab
is used.  If the
.B \-q
option is specified, less verbose status information is displayed.
.sp
.nf
.RS
.TP
EXAMPLE:
kadmin: ktremove -k /usr/local/var/krb5kdc/kadmind.keytab kadmin/admin
Entry for principal kadmin/admin with kvno 3 removed
	from keytab WRFILE:/usr/local/var/krb5kdc/kadmind.keytab.
kadmin:
.RE
.fi
.SH FILES
.TP "\w'<dbname>.kadm5.lock\ \ 'u"
principal.db
default name for Kerberos principal database
.TP
<dbname>.kadm5
KADM5 administrative database.  (This would be "principal.kadm5", if you
use the default database name.)  Contains policy information.
.TP
<dbname>.kadm5.lock
lock file for the KADM5 administrative database.  This file works
backwards from most other lock files.  I.e.,
.B kadmin
will exit with an error if this file does
.I not
exist.
.TP
.B Note:
The above three files are specific to db2 database.
.TP 
kadm5.acl
file containing list of principals and their
.B kadmin
administrative privileges.  See
.IR kadmind (8)
for a description.
.TP
kadm5.keytab
keytab file for
.I kadmin/admin
principal.
.TP
kadm5.dict
file containing dictionary of strings explicitly disallowed as
passwords.
.SH HISTORY
The
.B kadmin
prorgam was originally written by Tom Yu at MIT, as an interface to the
OpenVision Kerberos administration program.
.SH SEE ALSO
.IR kerberos (1),
.IR kpasswd (1),
.IR kadmind (8)
.SH BUGS
.PP
Command output needs to be cleaned up.
