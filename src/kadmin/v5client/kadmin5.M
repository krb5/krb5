.\" $Source$
.\" $Author$
.\" $Id$
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
.B /kadmind5@realm.
.IP \-m
specifies that multiple operations will be permitted for only one entry of the
administrative principal's password.

.SH DESCRIPTION
This utility provides a network administration interface to the Kerberos
master database.  Kerberos administrators use kadmin5 to register new
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
.B /kadmind5@realm.
.PP
One command may be specified on the command line, or if no command is provided,
an interactive command loop is entered for the administrator to enter commands.
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
.I kvno=<integer>
Specifies the key version number for the principal.
.TP i
.I maxlife=<integer>
Specifies the maximum ticket life for the principal in seconds.
.TP i
.I maxrenewlife=<integer>
Specifies the maximum renewable ticket life for the principal in seconds.
.TP i
.I expiration=<date>
Specifies the expiration date and time of the principal.  See below for the
format of
.I <date>.
.TP i
.I pwexpiration=<date>
Specifies the expiration date and time of the principal's password.  See below for the format of
.I <date>.
.TP i
.I salttype=[v5|v4|norealm|onlyrealm|special]
Indicates the salt type.
.TP i
.I [+/-]postdateable
Specifies that tickets for this principal [are/are not] postdateable.
.TP i
.I [+/-]forwardable
Specifies that tickets for this principal [are/are not] forwardable.
.TP i
.I [+/-]tgt_req
Specifies that TGT-based requests for this principal [are/are not] allowed.
.TP i
.I [+/-]renewable
Specifies that tickets for this principal [are/are not] renewable.
.TP i
.I [+/-]proxiable
Specifies that tickets for this principal [are/are not] proxiable.
.TP i
.I [+/-]dup_skey
Specifies that tickets issued by this service [may/may not] be encrypted
using the session key instead of the private key.
.TP i
.I [+/-]allow_tickets
Specifies that tickets for this principal [are/are not] allowed.
.TP i
.I [+/-]preauth
Specifies that preauthorization [is/is not] required for this principal.
.TP i
.I [+/-]hwauth
Specifies that hardware preauthorization [is/is not] required for this
principal.
.TP i
.I [+/-]pwchange_req
Specifies that a password change [is/is not] required for this principal.
.TP i
.I [+/-]server
Specifies that this principal [is/is not] allowed to be a service.
.TP i
.I [+/-]pwservice
Specifies that this principal [is/is not] the password changing service.
.TP i
.I [+/-]md5
Specifies that DES MD5 [is/is not] supported for this principal.

.SH Date Format
The format of <date>
may be one of the following, where
.I yy
is the last two digits of the year;
.I mm
is the month number (with a leading zero if less than 10);
.I dd
is the day number in the month (with a leading zero if less than 10);
.I HH
is the hour number (24-hour clock);
.I MM
is the minute number; and
.I SS
is the second number:
.TP i
.I yy.mm.dd.HH.MM.SS
e.g. 95.09.01.00.00.00 for midnight on September 1, 1995.
.TP i
.I yymmddHHMMSS
e.g. 950901000000 for midnight on September 1, 1995.
.PP
If the
.B strptime(3)
function is available, then the following formats are also supported.
.PP
.TP i
.I yymmddHHMM
e.g. 9509010000 for midnight on September 1, 1995.
.TP i
.I HHMMSS
e.g. 200000 for 8pm tonight.
.TP i
.I HHMM
e.g. 2100 for 9pm tonight.
.TP i
.I HH:MM:SS
e.g. 20:00:00 for 8pm tonight.
.TP i
.I HH:MM
e.g. 21:00 for 9pm tonight.
.TP i
.I locale-dependent short format (mm/dd/yy:HH:MM:SS) in U.S.
.e.g 01/09/95:00:00:00 for midnight on September 1, 1995.
.TP i
.I dd-<text-month>-yyyy:HH:MM:SS
e.g. 01-Sep-1995:00:00:00 for midnight on September 1, 1995.
.TP i
.I dd-<text-month>-yyyy:HH:MM
e.g. 01-Sep-1995:00:00 for midnight on September 1, 1995.
.PP
.SH SEE ALSO
kadmind5(8), kpasswd(1), strptime(3)
