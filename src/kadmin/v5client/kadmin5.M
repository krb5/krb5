.\" kadmin/v5client/kadmin5.M
.\"
.\" Copyright 1995 by the Massachusetts Institute of Technology.
.\"
.\" Export of this software from the United States of America may
.\"   require a specific license from the United States Government.
.\"   It is the responsibility of any person or organization contemplating
.\"   export to obtain such a license before exporting.
.\" 
.\" WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
.\" distribute this software and its documentation for any purpose and
.\" without fee is hereby granted, provided that the above copyright
.\" notice appear in all copies and that both that copyright notice and
.\" this permission notice appear in supporting documentation, and that
.\" the name of M.I.T. not be used in advertising or publicity pertaining
.\" to distribution of the software without specific, written prior
.\" permission.  M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" 
.\"
.TH KADMIN5 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kadmin5 \- administer a Kerberos principal database over the network.
.SH SYNOPSIS
.B kadmin5
[
.B \-r
.I realm
] [
.B \-p
.I principal
] [
.B \-c
.I ccache
] [
.B \-l
.I deltatime
] [
.B \-d
] [
.B \-s
] [
.B \-m
]
[ command ... ]
.br
.SH FLAGS
.PP
.IP \-r
.B realm
specifies the default realm.
.IP \-p
.B principal
specifies a principal name to use instead of the default 
.I user
.B /kadmin@realm.
.IP \-c
.B ccache
specifies a credentials cache to use instead of the default.
.IP \-l
.B deltatime
specifies the lifetime for an administrative ticket, if one needs to be
acquired.
.IP \-d
specifies that the credentials cache is to be deleted after use.
.IP \-s
specifies that the credentials cache is to be saved for further use.
.IP \-m
specifies that multiple operations will be permitted for only one entry of the
administrative principal's password.

.SH DESCRIPTION
This utility provides a network administration interface to the Kerberos
master database.  Kerberos administrators use
.I kadmin5
to register new
users and services with the master database; to remove old users and services
from the master database; to modify information about existing database
entries; and to create service key tables from entries in the database.
.PP
The
.I kadmin5
communicates over the network with the
.I kadmind5
program, which runs on the system where the Kerberos master database resides.
.I kadmind5
performs the database operations which
.I kadmin5
specifies.
.PP
Principals who may perform administrative operations are controlled by the
.I kadmind5
access control list.  The default administrative principal is
.I user
.B /kadmin@realm.
.PP
One command may be specified on the command line, or if no command is provided,
an interactive command loop is entered for the administrator to enter commands.
.PP
If a credentials cache is specified with
.I \-c
.B ccache,
then the default is not to delete the credentials cache.  Otherwise, the
default is to delete it.  The use of the
.I \-d
and
.I \-s
flags override this default behavior.
.PP
.SH AVAILABLE COMMANDS

The following is a list of commands and their aliases that the system
administrator may use to manipulate the database:

.IP show_principal,show
Show the Kerberos database entry for a principal.

.IP add_new_key,ank
Add new entry to Kerberos database (prompting for new password).

.IP change_pwd_key,cpw
Change key of an entry in the Kerberos database (prompting for new password).

.IP add_rnd_key,ark    
Add new entry to Kerberos database, using a random key.

.IP change_rnd_key,crk
Change key of an entry in the Kerberos database (selecting a new random key).

.IP add_key_type,akt
Add new key type to an existing Kerberos principal (prompting for old
password).

.IP del_key_type,dkt
Delete key type from an existing Kerberos principal (prompting for old
password).

.IP delete_entry,delent,del
Delete an entry from the database.

.IP extract_srvtab,xst,ex_st
Extract service key table entry/entries.

.IP extract_v4_srvtab,xst4
Extract service key table entry/entries in V4 format.

.IP modify_entry,modent
Modify database entry.

.IP rename_entry,renent
Rename database entry.

.IP list_db,ldb      
List database entries.

.IP change_working_directory,cwd,cd
Change working directory.

.IP print_working_directory,pwd
Print working directory.

.IP list_requests,lr,?
List available requests.

.IP quit,exit,q
Exit program.
.PP
.SH Principal Options
For the
.I add_new_key, add_rnd_key
and
.I modify_entry
commands, an optional list of principal options may be specified.  The
following options may be specified:
.TP i
.I maxlife=<deltatime>
Specifies the maximum ticket life for the principal.
.TP i
.I maxrenewlife=<deltatime>
Specifies the maximum renewable ticket life for the principal.
.TP i
.I expiration=<date>
Specifies the expiration date and time of the principal.
.TP i
.I pwexpiration=<date>
Specifies the expiration date and time of the principal's password.
.TP i
.I [+/-]<flag-value>
Selects a particular flag value.
.PP
.SH SEE ALSO
kadmind5(8), kpasswd(1)
