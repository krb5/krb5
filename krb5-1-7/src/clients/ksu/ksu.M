.\" Copyright (c) 1994 by the University of Southern California
.\"
.\" EXPORT OF THIS SOFTWARE from the United States of America may
.\"     require a specific license from the United States Government.
.\"     It is the responsibility of any person or organization contemplating
.\"     export to obtain such a license before exporting.
.\"
.\" WITHIN THAT CONSTRAINT, permission to copy, modify, and distribute
.\"     this software and its documentation in source and binary forms is
.\"     hereby granted, provided that any documentation or other materials
.\"     related to such distribution or use acknowledge that the software
.\"     was developed by the University of Southern California. 
.\"
.\" DISCLAIMER OF WARRANTY.  THIS SOFTWARE IS PROVIDED "AS IS".  The
.\"     University of Southern California MAKES NO REPRESENTATIONS OR
.\"     WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not
.\"     limitation, the University of Southern California MAKES NO
.\"     REPRESENTATIONS OR WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY
.\"     PARTICULAR PURPOSE. The University of Southern
.\"     California shall not be held liable for any liability nor for any
.\"     direct, indirect, or consequential damages with respect to any
.\"     claim by the user or distributor of the ksu software.
.\"
.\" KSU was writen by:  Ari Medvinsky, ari@isi.edu
.\" "
.TH KSU 1
.SH NAME
ksu \- Kerberized super-user    	
.SH SYNOPSIS
.B ksu 
[
.I target_user
] [
.B \-n
.I target_principal_name 
] [
.B \-c
.I source_cache_name
] [
.B \-k
] [
.B \-D
] [
.B \-r
.I time
] [
.B \-pf
] [
.B \-l 
.I lifetime
] [
.B \-zZ
] [
.B \-q
] [
.B \-e
.I command
[
.I args ...
] ] [
.B \-a 
[
.I args ...
] ] 
.br
.SH REQUIREMENTS
Must have Kerberos version 5 installed to compile ksu.
Must have a Kerberos version 5 server running to use ksu.
.br
.SH DESCRIPTION
.I ksu
is a Kerberized version of the su program that has two missions:
one is to securely change the real and effective user ID to that
of the target user, and the other is to create a new security context.
For the sake of clarity, all references to and attributes of
the user invoking the program will start with 'source' (e.g.
source user, source cache, etc.).  Likewise, all references
to and attributes of the target account will start with 'target'.
.br
.SH AUTHENTICATION
To fulfill the first mission, ksu operates in two phases: authentication
and authorization.  Resolving the target principal name is the
first step in authentication.  The user
can either specify his principal name with the
.B \-n
option
(e.g.
.B \-n
jqpublic@USC.EDU) or a default principal name will be assigned
using a heuristic described in the OPTIONS section (see
.B \-n
option).
The target user name must be the first argument to ksu; if not specified
root is the default.  If '.' is specified then the target user will be
the source user (e.g. ksu .). 
If the source user is root or the target user is the source user, no 
authentication or authorization takes place.  Otherwise, ksu looks
for an appropriate Kerberos ticket in the source cache.
.PP
The ticket can either be for
the end-server
or a ticket granting ticket (TGT) for the target principal's realm.  If the
ticket for the end-server is already in the cache, it's decrypted and
verified.  If it's not in the cache but the TGT is, the TGT is used to
obtain the ticket for the end-server.   The end-server ticket is then
verified.  If neither ticket is in the cache, but ksu is compiled
with the GET_TGT_VIA_PASSWD define, the user will be prompted
for a Kerberos password which will then be used to get a TGT.
If the user is logged in remotely and
does not have a secure channel, the password may be exposed.
If neither ticket is in the cache and GET_TGT_VIA_PASSWD is not defined,
authentication fails.
.br
.SH AUTHORIZATION
This section describes authorization of the source user when ksu
is invoked without the
.B \-e
option.
For a description of the
.B \-e
option, see the OPTIONS section.
.PP
Upon successful authentication, ksu checks whether the target principal
is authorized to access the target account.
In the target user's home directory, ksu attempts to access
two authorization files: .k5login and .k5users.  In the .k5login  
file each line contains the name of a
principal that is authorized to access the account.
.TP 12
For example:
jqpublic@USC.EDU
.br
jqpublic/secure@USC.EDU
.br
jqpublic/admin@USC.EDU
.PP
The format of .k5users is the same, except the
principal name may be followed by a list of commands that
the principal is authorized to execute. (see the
.B \-e
option in the OPTIONS section for details).
.PP
Thus if the target principal
name is found in the .k5login file the source user is authorized to access
the target account. Otherwise ksu looks in the .k5users file.
If the target principal name is found without any trailing commands
or followed only by '*' then the source user is authorized.  
If either .k5login or .k5users exist but an appropriate entry for the target
principal does not exist then access is denied. If neither
file exists then the principal will be granted access 
to the account according to the aname\->lname mapping rules (see
.IR krb5_anadd(8) 
for more details).
Otherwise, authorization fails.
.br
.SH EXECUTION OF THE TARGET SHELL
Upon successful authentication and authorization, ksu
proceeds in a similar fashion to su.  The environment
is unmodified with the exception of USER, HOME and SHELL variables.
If the target user is not root, USER gets set to the target user
name. Otherwise USER remains unchanged. Both HOME and SHELL are
set to the target login's default values.
In addition, the environment variable KRB5CCNAME gets set to the
name of the target cache.
The real and effective user ID are changed to that of the
target user.  The target user's shell is then invoked
(the shell name is specified in the password file).
Upon termination of the shell, ksu deletes the target cache (unless
ksu is invoked with the
.B \-k option).
This is implemented by first doing a fork and then an exec, instead
of just exec, as done by su.
.br
.SH CREATING A NEW SECURITY CONTEXT
.PP
Ksu can be used to create a new security context for the
target program (either the target
shell, or command specified via the -e option).
The target program inherits a set
of credentials from the source user.
By default, this set includes all of the credentials
in the source cache plus any
additional credentials obtained during authentication.
The source user is able to limit the credentials in this set
by using -z or -Z option.
-z restricts the copy of tickets from the source cache
to the target cache to only the tickets where client ==
the target principal name.  The -Z option
provides the target user with a fresh target cache
(no creds in the cache). Note that for security reasons,
when the source user is root and target user is non-root,
-z option is the default mode of operation. 

While no authentication takes place if the source user
is root or is the same as the target user, additional
tickets can still be obtained for the target cache.
If -n is specified and no credentials can be copied to the target
cache,  the  source user is prompted for a Kerberos password
(unless -Z specified or GET_TGT_VIA_PASSWD is undefined). If
successful,  a  TGT is obtained from the Kerberos server and
stored in the target cache.  Otherwise,
if a password is not provided (user hit return)
ksu continues  in  a
normal  mode  of  operation (the target cache will
not contain the desired TGT).
If the wrong password is typed in, ksu fails.
.PP
\fISide Note:\fP during authentication, only the tickets that could be
obtained without providing a password are cached in
in the source cache.
.SH OPTIONS
.TP 10
\fB\-n \fItarget_principal_name
Specify a Kerberos target principal name.
Used in authentication and authorization
phases of ksu.

If ksu is invoked without
.B \-n,
a default principal name is
assigned via the following heuristic:

\fICase 1:\fP source user is non-root.
.br
If the target user is the source user the default principal name
is set to the default principal of the source cache. If the
cache does not exist then the default principal name is set to
target_user@local_realm.
If the source and target users are different and
neither ~target_user/.k5users
nor ~target_user/.k5login exist then
the default principal name is
target_user_login_name@local_realm. Otherwise,
starting with the first principal listed below,
ksu checks if the principal is authorized
to  access the target account and whether
there is a legitimate ticket for that principal
in the source cache. If both conditions are met
that principal becomes the default target principal,
otherwise go to the next principal.

a) default principal of the source cache
.br
b) target_user@local_realm
.br
c) source_user@local_realm

If a-c fails try any principal for which there is
a ticket in the source cache and that is
authorized to access the target account.
If that fails select the first principal that
is authorized to access the target account from
the above list.
If none are authorized and ksu is configured with PRINC_LOOK_AHEAD
turned on, select the default principal as follows:

For each candidate in the above list,
select an authorized principal that has
the same realm name and first part
of the principal name equal to the prefix of the candidate.
For example if candidate a) is jqpublic@ISI.EDU and jqpublic/secure@ISI.EDU
is authorized to access the target account then the default principal
is set to jqpublic/secure@ISI.EDU.

\fICase 2:\fP source user is root.
.br
If the target user is non-root then the
default principal name is target_user@local_realm.
Else, if the source cache exists the default
principal name is set to the default principal
of the source cache. If the source cache does not
exist, default principal name is set to
root@local_realm.
.TP 10
\fB\-c \fIsource_cache_name
Specify source cache name (e.g.
.B \-c
FILE:/tmp/my_cache).
If
.B \-c
option is not used then the
name is obtained from KRB5CCNAME environment variable.
If KRB5CCNAME is not defined the source cache name
is set to krb5cc_<source uid>.
The target cache name is automatically
set to krb5cc_<target uid>.(gen_sym()),
where gen_sym generates a new number such that
the resulting cache does not already exist.
.br
For example: krb5cc_1984.2
.TP 10
\fB\-k
Do not delete the target cache upon termination of the
target shell or a command (
.B \-e
command).
Without
.B \-k,
ksu deletes the target cache.
.TP 10
\fB\-D
turn on debug mode.
.TP 10
\fITicket granting ticket options: -l lifetime -r time -pf\fP
The ticket granting ticket options only apply to the
case where there are no appropriate tickets in
the cache to authenticate the source user. In this case
if ksu is configured to prompt users for a
Kerberos password (GET_TGT_VIA_PASSWD is defined),
the ticket granting
ticket options that are specified will be used
when getting a ticket granting ticket from the Kerberos
server.
.TP 10
\fB\-l \fIlifetime
option specifies the lifetime to be
requested for the ticket; if this option is not
specified, the  default ticket lifetime
(configured by each site) is used instead.
.TP 10
\fB\-r \fItime
option  specifies  that  the  RENEWABLE  option
should be requested for the ticket, and specifies
the desired total lifetime of the ticket.
.TP 10
\fB\-p
option specifies that the PROXIABLE option should  be
requested for the ticket.
.TP 10
\fB\-f
option specifies that the FORWARDABLE  option  should
be requested for the ticket.
.TP 10
\fB\-z
restrict the copy of tickets from the source cache
to the target cache to only the tickets where client ==
the target principal name. Use the
.B \-n
option
if you want the tickets for other then the default
principal. Note that the
.B \-z 
option is mutually
exclusive with the -Z option.
.TP 10
\fB\-Z
Don't copy any tickets from the source cache to the
target cache. Just create a fresh target cache,
where the default principal name of the cache is
initialized to the target principal name.  Note that
.B \-Z
option is mutually
exclusive with the -z option.
.TP 10
\fB\-q
suppress the printing of status messages.
.TP 10
\fB\-e \fIcommand [args ...]
ksu proceeds exactly the same as if it was invoked without the
.B \-e
option,
except instead of executing the target shell, ksu executes the
specified command (Example of usage: ksu bob
.B \-e
ls
.B \-lag).

\fIThe authorization algorithm for -e is as follows:\fP

If the source user is root or source user == target user,
no authorization takes place and             
the command is executed.  If source user id != 0, and ~target_user/.k5users
file does not exist, authorization fails.
Otherwise, ~target_user/.k5users file must have an
appropriate entry for target principal
to get authorized.

\fIThe .k5users file format:\fP

A single principal entry on each line
that may be followed by a list of commands that
the principal is authorized to execute.
A principal name followed by a '*' means
that the user is authorized to execute
any command. Thus, in the following example:

jqpublic@USC.EDU ls mail /local/kerberos/klist
.br
jqpublic/secure@USC.EDU *
.br
jqpublic/admin@USC.EDU

jqpublic@USC.EDU is only authorized to execute ls, mail
and klist commands. jqpublic/secure@USC.EDU is authorized
to execute any command. jqpublic/admin@USC.EDU is not
authorized to execute any command.  Note, that
jqpublic/admin@USC.EDU is authorized to execute
the target shell (regular ksu, without the
.B \-e
option) but jqpublic@USC.EDU is not.

The commands listed after the principal name must
be either a full path names or just the program name.
In the second case, CMD_PATH specifying the location
of authorized programs must be defined at the
compilation time of ksu.               

\fIWhich command gets executed ?\fP

If the source user is root or
the target user is the source user or 
the user
is authorized to execute any command ('*' entry)
then command can be either a full or a relative
path leading to the target program.
Otherwise, the user must specify either a full
path or just the program name.
.TP 10
\fB\-a \fIargs
specify arguments to be passed to the target shell.
Note: that all flags and parameters following -a
will be passed to the shell, thus all options
intended for ksu must precede
.B \-a.
The
.B \-a
option can be used to simulate the
.B \-e
option if used as follows:
.B \-a
.B \-c
[command [arguments]].
.B \-c
is interpreted by the c-shell to execute the command.
.PP
.SH INSTALLATION INSTRUCTIONS
ksu can be compiled with the following 4 flags (see the Imakefile):
.TP 10
\fIGET_TGT_VIA_PASSWD\fP 
in case no appropriate tickets are found in the source
cache, the user will be prompted for a Kerberos
password.  The password is then used to get a
ticket granting ticket from the Kerberos server.
The danger of configuring ksu with this macro is
if the source user is loged in remotely and does not
have a secure channel, the password may get exposed.
.TP 10
\fIPRINC_LOOK_AHEAD\fP
during the resolution of the default principal name,
PRINC_LOOK_AHEAD enables ksu to find principal names          
in the .k5users file as described in the OPTIONS section
(see -n option).      
.TP 10
\fICMD_PATH\fP
specifies a list of directories containing programs
that users are authorized to execute (via .k5users file). 
.TP 10
\fIHAS_GETUSERSHELL\fP
If the source user is non-root, ksu insists that
the target user's shell to be invoked
is a "legal shell". getusershell(3) is called to obtain
the names of "legal shells".  Note that the target user's    
shell is obtained from the passwd file.
.TP 10
SAMPLE CONFIGURATION:
KSU_OPTS = -DGET_TGT_VIA_PASSWD 
-DPRINC_LOOK_AHEAD -DCMD_PATH='"/bin /usr/ucb /local/bin"
.TP 10
PERMISSIONS FOR KSU
ksu should be owned by root and have the set user id  bit turned on.   
.TP 10
END-SERVER ENTRY     

ksu attempts to get a ticket for the end server just as Kerberized
telnet and rlogin.  Thus, there must be an entry for the server in the
Kerberos database (e.g. host/nii.isi.edu@ISI.EDU).  The keytab file must
be in an appropriate location.

.SH SIDE EFFECTS
ksu deletes all expired tickets from the source cache. 
.SH AUTHOR OF KSU:	GENNADY (ARI) MEDVINSKY
