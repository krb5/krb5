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
.TH KDC.CONF 5
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
.IP kdc_ports
This relation lists the ports which the Kerberos server should listen
on, by default.  This list is a comma separated list of integers.  If
this relation is not specified, the compiled-in default is usually
port 88 and port 750.
.SH REALMS SECTION
Each tag in the
.I [realms]
section of the file names a Kerberos realm.  The value of the tag is a
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

.IP kdc_ports
This
.B string
specifies the list of ports that the KDC is to listen to for this realm.  
By default, the value of 
.I kdc_ports
as specified in the 
.I [kdcdefaults] 
section is used.

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
