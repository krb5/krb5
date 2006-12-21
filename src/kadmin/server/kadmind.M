.TH KADMIND 8
.SH NAME
kadmind \- KADM5 administration server
.SH SYNOPSIS
.B kadmind
[\fB\-x\fP \fIdb_args\fP] [\fB-r\fP \fIrealm\fP] [\fB\-m\fP] [\fB\-nofork\fP] [\fB\-port\fP
\fIport-number\fP]
.SH DESCRIPTION
This command starts the KADM5 administration server.  If the database is db2, 
the administration server runs on the master Kerberos server, which stores the KDC
prinicpal database and the KADM5 policy database. If the database is LDAP,
the administration server and the KDC server need not run on the same machine.  
.B Kadmind
accepts remote requests to administer the information in these
databases.  Remote requests are sent, for example, by
.IR kadmin (8)
and the
.IR kpasswd (1)
command, both of which are clients of
.BR kadmind .
.PP
.B kadmind
requires a number of configuration files to be set up in order
for it to work:
.TP "\w'kdc.conf\ \ 'u"
kdc.conf
The KDC configuration file contains configuration informatin for the KDC
and the KADM5 system.  
.B Kadmind
understands a number of variable settings in this file, some of whch are
mandatory and some of which are optional.  See the CONFIGURATION VALUES
section below.
.TP
keytab
.B Kadmind
requires a keytab containing correct entries for the 
.I kadmin/admin
and
.I kadmin/changepw
principals for every realm that kadmind will answer requests for.  The
keytab can be created with the
.IR kadmin (8)
client.  The location of the keytab is determined by the
.I admin_keytab
configuration variable (see CONFIGURATION VALUES).
.TP
ACL file
.BR Kadmind 's
ACL (access control list) tells it which principals are allowed to
perform KADM5 administration actions.  The path of the ACL file is
specified via the acl_file configuration variable (see CONFIGURATION
VALUES).  The syntax of the ACL file is specified in the ACL FILE SYNTAX
section below.
.PP
After the server begins running, it puts itself in the background and
disassociates itself from its controlling terminal.
.SH OPTIONS
.TP 
\fB\-x\fP \fIdb_args\fP
specifies the database specific arguments.

Options supported for LDAP database are:
.sp 
.nf 
.RS 12
\-x nconns=<number_of_connections>
.fi
specifies the number of connections to be maintained per LDAP server.

.nf
\-x host=<ldapuri>
specifies the LDAP server to connect to by a LDAP URI.

\-x binddn=<binddn>
.fi
specifies the DN of the object used by the administration server to bind to the LDAP server. 
This object should have the read and write rights on the realm container, principal container
and the subtree that is referenced by the realm.

\-x bindpwd=<bind_password>
.fi
specifies the password for the above mentioned binddn. It is recommended not to use this option.
Instead, the password can be stashed using the stashsrvpw command of kdb5_ldap_util.
.RE
.fi
.TP
\fB\-r\fP \fIrealm\fP
specifies the default realm that kadmind will serve; if it is not
specified, the default realm of the host is used.  
.B kadmind
will answer requests for any realm that exists in the local KDC database
and for which the appropriate principals are in its keytab.
.TP
.B \-m
specifies that the master database password should be fetched from the
keyboard rather than from a file on disk.  Note that the server gets the
password prior to putting itself in the background; in combination with
the -nofork option, you must place it in the background by hand.
.TP
.B \-nofork
specifies that the server does not put itself in the background and does
not disassociate itself from the terminal.  In normal operation, you
should always allow the server place itself in the background.
.TP
\fB\-port\fP \fIport-number\fB
specifies the port on which the administration server listens for
connections.  The default is is controlled by the 
.I kadmind_port
configuration variable (see below).
.SH CONFIGURATION VALUES
.PP
In addition to the relations defined in kdc.conf(5), kadmind
understands the following relations, all of which should
appear in the [realms] section:
.TP
acl_file
The path of kadmind's ACL file.  Mandatory.  No default.
.TP
dict_file
The path of kadmind's password dictionary.  A principal with any
password policy will not be allowed to select any password in the
dictionary.  Optional.  No default.
.TP
admin_keytab
The name of the keytab containing entries for the principals
.I kadmin/admin
and
.I kadmin/changepw
in each realm that
.B kadmind
will serve.  The default is the value of the 
.SM KRB5_KTNAME
environment variable, if defined.  Mandatory.
.TP
kadmind_port
The
.SM TCP
port on which
.B kadmind
will listen.  The default is 749.
.SH ACL FILE SYNTAX
.PP
The ACL file controls which principals can or cannot perform which
administrative functions.  For operations that affect principals, the
ACL file also controls which principals can operate on which other
principals.  This file can contain comment lines, null lines or lines
which contain ACL entries.  Comment lines start with the sharp sign
(\fB\&#\fP) and continue until the end of the line.  Lines containing ACL
entries have the format of
.B principal
.I whitespace
.B operation-mask
[\fIwhitespace\fP \fBoperation-target\fP]
.PP
Ordering is important.  The first matching entry is the one which will
control access for a particular principal on a particular principal.
.PP
.IP principal
may specify a partially or fully qualified Kerberos version 5
principal name.  Each component of the name may be wildcarded using
the asterisk (
.B *
) character.
.IP operation-target
[Optional] may specify a partially or fully qualified Kerberos version 5
principal name.  Each component of the name may be wildcarded using the
asterisk (
.B *
) character.
.IP operation-mask
Specifies what operations may or may not be peformed by a principal
matching a particular entry.  This is a string of one or more of the
following list of characters or their upper-case counterparts.  If the
character is upper-case, then the operation is disallowed.  If the
character is lower-case, then the operation is permitted.
.RS
.TP 5
.B a
[Dis]allows the addition of principals or policies in the database.
.sp -1v
.TP
.B d
[Dis]allows the deletion of principals or policies in the database.
.sp -1v
.TP
.B m
[Dis]allows the modification of principals or policies in the database.
.sp -1v
.TP
.B c
[Dis]allows the changing of passwords for principals in the database.
.sp -1v
.TP
.B i
[Dis]allows inquiries to the database.
.sp -1v
.TP
.B l
[Dis]allows the listing of principals or policies in the database.
.sp -1v
.TP
.B x
Short for
.IR admcil .
.sp -1v
.TP
.B \&*
Same as
.BR x .
.RE
Some examples of valid entries here are:
.TP
.I user/instance@realm adm
A standard fully qualified name.  The
.B operation-mask
only applies to this principal and specifies that [s]he may add,
delete or modify principals and policies, but not change anybody
else's password.
.TP
.I user/instance@realm cim service/instance@realm
A standard fully qualified name and a standard fully qualified target.  The
.B operation-mask
only applies to this principal operating on this target and specifies that
[s]he may change the target's password, request information about the
target and modify it.
.TP
.I user/*@realm ac
A wildcarded name.  The
.B operation-mask
applies to all principals in realm "realm" whose first component is
"user" and specifies that [s]he may add principals and change
anybody's password.
.TP
.I user/*@realm i */instance@realm
A wildcarded name and target.  The
.B operation-mask
applies to all principals in realm "realm" whose first component is
"user" and specifies that [s]he may perform
inquiries on principals whose second component is "instance" and realm
is "realm".
.SH FILES
.TP "\w'<dbname>.kadm5.lock\ 'u"
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
administrative privileges.  See above for a description.
.TP
kadm5.keytab
keytab file for
.I kadmin/admin
principal.
.TP
kadm5.dict
file containing dictionary of strings explicitly disallowed as
passwords.
.SH SEE ALSO
kpasswd(1), kadmin(8), kdb5_util(8), kadm5_export(8), kadm5_import(8),
kdb5_ldap_util(8)

