.\" $Source$
.\" $Author$
.\" $Id$
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
.TH KADMIND5 8 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kadmind5 \- network daemon for Kerberos version 5 database information
.SH SYNOPSIS
.B kadmind5
[
.B \-m
] [
.B \-n
] [
.B \-a
aclfile
] [
.B \-d
dbname
] [
.B \-e
enctype
] [
.B \-k
mkeytype
] [
.B \-p
port
] [
.B \-r
realm
] [
.B \-s
keystash
] [
.B \-t
timeout
] [
.B \-D
debugmask
] [
.B \-M
mkeyname
] [
.B \-T
keytab
]
.SH DESCRIPTION
.I kadmind5
is the network database server for the Kerberos version 5
password-changing and administration tools.

.SH FLAGS
.PP
.B Database, Key and Realm flags
.IP \-r 
.B realm
specifies the realm that this server is to administer.  The default is
the local realm.
.IP \-d
.B dbname
specifies the location of the database.
.IP \-M
.B mkeyname
specifies the name of the master key.
.IP \-k
.B mkeytype
specifies the master key type.
.IP \-m
Indicates that the master key name is to be entered manually.
.IP \-e
.B enctype
specifies the encryption type which is to be used.
.IP \-s
.B keystash
specifies the key stash file ( created by
.I kdb5_stash(8)
) used for automatic restart.
.IP \-T
.B keytab
specifies the name of the service key table. 
.PP
.B ACL flag
.IP \-a
.B aclfile
specifies the location of the ACL file.  This file controls remote
principals' abilities to perform administrative functions.  See the
ACL FILE section below for the format of this file.
.PP
.B Connection flags
.IP \-t
Indicates that the server is to terminate a connection if it remains
inactive for
.B timeout
seconds.
.IP \-p
Indicates that the administrative server is to listen on port
.B port
instead of the default port.
.PP
.B Debugging flags
.IP \-D
Enables certain debugging features and messages selected by
.B debugmask.
.IP \-n
Specifies that the daemon is not to operate in the background.
.PP

.SH ACL FILE
.PP
The ACL file controls which principals can or cannot perform which
administrative functions on which principals.
This file can contain comment lines, null
lines or lines which contain ACL entries.  Comment lines start with
the sharp sign (
.B \#
) and continue until the end of the line.  Lines containing ACL
entries have the format of
.B principal
.I whitespace
.B operation-mask
[
.I whitespace
.B operation-target
]

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
.TP i
.I a
[Dis]allows the addition of principals from the database.
.TP i
.I d
[Dis]allows the deletion of principals from the database.
.TP i
.I m
[Dis]allows the modification of principals in the database.
.TP i
.I c
[Dis]allows the changing of passwords for principals in the database.
.TP i
.I o
[Dis]allows the changing of the principal's own password in the
database.
.TP i
.I i
[Dis]allows inquiries to the database.
.TP i
.I e
[Dis]allows extraction of service key entries.
.TP i
.I p
Short for
.I adm.
.TP i
.I w
Short for
.I pw.
.TP i
.I x or *
Short for
.I admcoie.
.PP
Some examples of valid entries here are:
.TP 2i
.I user/instance@realm po
A standard fully qualified name.  The
.B operation-mask
only applies to this principal and specifies that [s]he may add,
delete or modify principals and change his/her own password, but not
anybody elses.
.TP 2i
.I user/instance@realm ceim service/instance@realm
A standard fully qualified name and a standard fully qualified target.  The
.B operation-mask
only applies to this principal operating on this target and specifies that
[s]he may change the target's password, extract its service key, request
information about the target and modify it.
.TP 2i
.I user/*@realm aw
A wildcarded name.  The
.B operation-mask
applies to all principals in realm "realm" whose first component is
"user" and specifies that [s]he may add principals and change anybody
else's password or change his/her own.
.TP 2i
.I user/*@realm ei */instance@realm
A wildcarded name and target.  The
.B operation-mask
applies to all principals in realm "realm" whose first component is
"user" and specifies that [s]he may extract service keys for or perform
inquiries on principals whose second component is "instance" and realm
is "realm".
.TP 2i
.I * o
The catchall entry.  The
.B operation-mask
applies to all principals and indicates that they may change their own
passwords.  This entry is the default entry.

.SH SEE ALSO
kpasswd(1), kadmin5(8)
.SH BUGS

