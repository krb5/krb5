.\" admin/edit/kdb5_edit.M
.\"
.\" Copyright 1990 by the Massachusetts Institute of Technology.
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
.\" permission.  Furthermore if you modify this software you must label
.\" your software as modified software and not distribute it in such a
.\" fashion that it might be confused with the original M.I.T. software.
.\" M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" 
.\"
.TH KDB5_EDIT 8
.SH NAME
kdb5_edit \- edit a Kerberos V5 principal database
.SH SYNOPSIS
.B kdb5_edit
[
.B \-r
.I realm
] [
.B \-d
.I dbname
] [
.B \-k
.I keytype
] [
.B \-M
.I mkeyname
] [
.B \-e
.I enctype
] [
.B \-m
] [
.B \-R
.I command
] [
.B \-s
.I script
] [
.B \-f
.I stashfile
]
.br
.SH DESCRIPTION
.I kdb5_edit
allows an administrator to add, delete, and edit entries in a Kerberos
version 5 principal database.
After themaster key is verified, commands are to
.I kdb5_edit
are issued using one of three mechanisms.  If a single command is supplied 
using the
.B \-R
.I command
argument, then that single command is processed and execution ceases.  If a
script file is provided using the 
.B \-s
.I script
argument, then commands are read from this file until either an error occurs
or an end of file is detected.  Finally, if neither a command or a script is
specified, the invoker is placed into a shell-like command loop, from which
[s]he may issue commands to modify the
database.  
.PP
The
.B \-r
.I realm
option specifies the realm of the database;
by default the realm returned by
.IR krb5_default_local_realm (3)
is used.
.PP
The
.B \-d
.I dbname
option specifies the name under which the principal database is stored;
by default the database is in DEFAULT_DBM_FILE (defined in <krb5/osconf.h>).
.PP
The
.B \-k
.I keytype
option specifies the key type of the master key in the database; the default is
the string representation of DEFAULT_KDC_KEYTYPE (defined in <krb5/osconf.h>).
.PP
The
.B \-f
.I stashfile
option specifies the filename of the stashed V5 master key. The default is
defined as DEFAULT_KEYFILE_STUB in <krb5/osconf.h> and is 
typically $(prefix)/lib/krb5kdc/.k5.REALMNAME. (In previous
releases, this would have been /.k5.REALMNAME.)
.PP
The
.B \-M
.I mkeyname
option specifies the principal name for the master key in the database;
the default is KRB5_KDB_M_NAME (defined in <krb5/kdb.h>).
.PP
The
.B \-e
.I enctype
option specifies the encryption type to be used when placing entries in
the database; the default is the string representation of DEFAULT_KDC_ETYPE
(defined in <krb5/osconf.h>).
.PP
The
.B \-m
option specifies that the master database password should be fetched
from the keyboard rather than from a file on disk.
.SH AVAILABLE COMMANDS

The following is a list of commands and their aliases that the system
administrator may use to manipulate the database:

.IP add_new_key,ank
Add new entry to Kerberos database (prompting for password)

.IP change_pwd_key,cpw      
Change key of an entry in the Kerberos database (prompting for password)

.IP add_rnd_key,ark         
Add new entry to Kerberos database, using a random key

.IP change_rnd_key,crk      
Change key of an entry in the Kerberos database (select a new random key)

.IP delete_entry,delent,del
Delete an entry from the database

.IP extract_srvtab,xst,ex_st
Extract service key table

.IP extract_v4_srvtab,xst4  
Extract service key table

.IP modify_entry,modent
Modify entry

.IP list_db,ldb             
List database entries

.IP dump_db,ddb             
Dump database entries to a file

.IP load_db,lddb            
Load database entries from a file

.IP set_dbname,sdbn         
Change database name

.IP enter_master_key,emk    
Enter the master key for a database

.IP change_working_directory,cwd,cd
Change working directory

.IP print_working_direcotry,pwd
Print working directory

.IP list_requests,lr,?     
List available requests.

.IP quit,exit,q            
Exit program.

.SH SEE ALSO
krb5(3), krb5kdc(8), ss(3)
.SH BUGS

