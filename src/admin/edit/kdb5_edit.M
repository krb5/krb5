.\" $Source$
.\" $Author$
.\" $Id$
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
.\" permission.  M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" 
.\"
.TH KDB5_EDIT 8 "Kerberos Version 5.0" "MIT Project Athena"
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
]
.br
.SH DESCRIPTION
.I kdb5_edit
allows an administrator to add, delete, and edit entries in a Kerberos
version 5 principal database.
After the master key is verified, the administrator is placed into a
shell-like command loop, from which he may issue commands to modify the
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
option specifies the key type (as an ascii representation of a decimal
number) of the master key in the database; the default is
DEFAULT_KDC_KEYTYPE (defined in <krb5/osconf.h>).
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
option specifies the encryption type (as an ascii representation of a decimal
number) to be used when placing entries in
the database; the default is DEFAULT_KDC_ETYPE (defined in <krb5/osconf.h>).
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
This routine must be run interactively.  There is no command-line interface.
