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
.TH KDC.CONF 5 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
kdc.conf \- Kerberos V5 KDC configuration file
.SH DESCRIPTION
.I kdc.conf
specifies per-realm configuration data to be used by the Kerberos V5
Authentication Service and Key Distribution Center (AS/KDC).  This
includes database, key and per-realm defaults.
.PP
The 
.I kdc.conf
file uses the same format as the
.I krb5.conf
file.  For a basic description of the syntax, please refer to the
.I krb5.conf
description.
.PP
Each section in
.I kdc.conf
describes a particular realm and the individual tags describe that
parameter value for that realm.  The following tags are currently
used:
.IP database_name
This
.B string
specifies the location of the Kerberos database for this realm.

.IP master_key_name
This
.B string
specifies the name of the master key.

.IP master_key_type
This
.B integer
represents the master key's key type (see krb5.h for key type values).

.IP encryption_type
This
.B integer
represents the encryption type used for this realm (see krb5.h for
encryption type values).

.IP key_stash_file
This
.B string
specifies the location where the master key has been stored with
.I kdb5_stash.

.IP port
This
.B integer
specifies the primary port that the KDC is to listen to for this
realm.

.IP max_life
This
.B string
specifes the maximum time period that a ticket may be valid for in
this realm.  The format of this string may be one of the following:
.in +1i
.I <days>-<hours>:<minutes>:<seconds>

.I <days>d <hours>h <minutes>m <seconds>s

.I <hours>:<minutes>:<seconds>

.I <hours>h <minutes>m <seconds>s

.I <hours>:<minutes>

.I <hours>h <minutes>m

.I <seconds>

.in -1i
.IP max_renewable_life
This
.B string
specifies the maximum time period that a ticket may be renewed for in
this realm.  The format is the same as for
.I max_life.

.SH FILES 
/usr/local/lib/krb5kdc/kdc.conf

.SH SEE ALSO
krb5.conf(5), krb5kdc(8)
