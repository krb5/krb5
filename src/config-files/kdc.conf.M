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
The following sections are currently used in the
.I kdc.conf
file:
.IP [kdcdefaults]
Contains parameters which control the overall behaviour of the KDC.
.IP [realms]
Contains subsections keyed by Kerberos realm names which describe per-realm
KDC parameters.
.SH KDCDEFAULTS SECTION
The following relations are defined in the
.I [kdcdefaults]
section:
.IP primary_ports
This relation lists the primary ports (e.g. ports to serve Kerberos version
5 requests) to listen on.  This list is a comma separated list of integers.
If supplied, this list serves as a base list of ports to listen on.  If any
other ports are named in the
.I [realms]
section explicitly; or are named by
.B kdc
relations specifying this host in the
.I krb5.conf
file specified in the
.B profile
entry for a particular realm, then these ports are also listened on.
.IP secondary_ports
This relation lists the secondary ports (e.g. ports to serve Kerberos version
4 requests) to listen on.  If supplied, this list serves as a base list of
ports to listen on.  If any other ports are named in the
.I [realms]
section explicitly; or are named by
.B v4kdc
relations specifying this host in the
.I krb5.conf
file specified in the
.B profile
entry for a particular realm, then these ports are also listened on.
Further, if this list is specified and the first element is
.I \-1
then no secondary ports are listened to, even if specified in the
.I [realms]
section.
.SH REALMS SECTION
Each tag in the
.I [realms]
section of the file names a Kerbveros realm.  The value of the tag is a
subsection where the relations in that subsection define KDC parameters for
that particular realm.
.PP
For each realm, the following tags may be specified in the
.I [realms]
subsection:
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
.B key type string
represents the master key's key type.

.IP encryption_type
This
.B encryption type string
represents the encryption type used for this realm.

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

.IP secondary_port
This
.B integer
specifies the secondary port that the KDC is to listen to for this
realm.

.IP max_life
This
.B delta time string
specifes the maximum time period that a ticket may be valid for in
this realm.  

.IP max_renewable_life
This
.B delta time string
specifies the maximum time period that a ticket may be renewed for in
this realm. 

.IP default_principal_expiration
This
.B absolute time string
specifies the default expiration date of principals created in this realm.

.IP default_principal_flags
This
.B flag string
specifies the default attributes of principals created in this realm.

.IP supported_keytypes
This list of
.B key
:
.B salt
strings specifies the default key/salt combinations of principals for this
realm.

.SH FILES 
/usr/local/lib/krb5kdc/kdc.conf

.SH SEE ALSO
krb5.conf(5), krb5kdc(8)
