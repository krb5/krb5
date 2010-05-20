.\" Copyright 1995, 2008 by the Massachusetts Institute of Technology.
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
.IP kdc_tcp_ports
This relation lists the ports on which the Kerberos server should
listen for TCP connections by default.  This list is a comma separated
list of integers.
If this relation is not specified, the compiled-in default is not to
listen for TCP connections at all.

If you wish to change this (which we do not recommend, because the
current implementation has little protection against denial-of-service
attacks), the standard port number assigned for Kerberos TCP traffic
is port 88.
.IP v4_mode
This 
.B string
specifies how the KDC should respond to Kerberos IV packets. Valid
values for this relation are the same as the valid arguments to the
.B -4
flag to
.BR krb5kdc .
If this relation is not specified, the compiled-in default of
.I none
is used.

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

.IP acl_file
This
.B string
specifies the location of the access control list (acl) file that
kadmin uses to determine which principals are allowed which permissions
on the database. The default value is /usr/local/var/krb5kdc/kadm5.acl.

.IP admin_keytab
This
.B string
Specifies the location of the keytab file that kadmin uses to
authenticate to the database.  The default value is
/usr/local/var/krb5kdc/kadm5.keytab.

.IP database_name
This
.B string
specifies the location of the Kerberos database for this realm.

.IP default_principal_expiration
This
.B absolute time string
specifies the default expiration date of principals created in this realm.

.IP default_principal_flags
This
.B flag string
specifies the default attributes of principals created in this realm.
The format for the string is a comma-separated list of flags, with '+'
before each flag to be enabled and '-' before each flag to be
disabled.  The default is for postdateable, forwardable, tgt-based,
renewable, proxiable, dup-skey, allow-tickets, and service to be
enabled, and all others to be disabled.

There are a number of possible flags: 
.RS
.TP
.B postdateable
Enabling this flag allows the principal to obtain postdateable tickets.
.TP
.B forwardable
Enabling this flag allows the principal to obtain forwardable tickets.
.TP
.B tgt-based
Enabling this flag allows a principal to obtain tickets based on a
ticket-granting-ticket, rather than repeating the authentication
process that was used to obtain the TGT.
.TP
.B renewable
Enabling this flag allows the principal to obtain renewable tickets.
.TP
.B proxiable
Enabling this flag allows the principal to obtain proxy tickets.
.TP
.B dup-skey
Enabling this flag allows the principal to obtain a session key for
another user, permitting user-to-user authentication for this principal.
.TP
.B allow-tickets
Enabling this flag means that the KDC will issue tickets for this
principal.  Disabling this flag essentially deactivates the principal
within this realm.
.TP
.B preauth
If this flag is enabled on a client principal, then that principal is
required to preauthenticate to the KDC before receiving any tickets.
On a service principal, enabling this flag means that service tickets
for this principal will only be issued to clients with a TGT that has
the preauthenticated ticket set.
.TP
.B hwauth
If this flag is enabled, then the principal is required to
preauthenticate using a hardware device before receiving any tickets.
.TP
.B pwchange
Enabling this flag forces a password change for this principal.
.TP
.B service
Enabling this flag allows the the KDC to issue service tickets for this
principal.
.TP
.B pwservice
If this flag is enabled, it marks this principal as a password change
service.  This should only be used in special cases, for example, if a
user's password has expired, the user has to get tickets for that
principal to be able to change it without going through the normal
password authentication.
.RE

.IP dict_file
This
.B string
location of the dictionary file containing strings that are not allowed
as passwords.  If this tag is not set or if there is no policy assigned
to the principal, then no check will be done.

.IP kadmind_port
This
.B port number
specifies the port on which the kadmind daemon is to listen for this
realm.

.IP kpasswd_port
This
.B port number
specifies the port on which the kadmind daemon is to listen for this
realm.

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

.IP kdc_tcp_ports
This
.B string
specifies the list of ports that the KDC is to listen to
for TCP requests for this realm.  By default, the value of
.I kdc_tcp_ports
as specified in the
.I [kdcdefaults]
section is used.

.IP master_key_name
This
.B string
specifies the name of the principal associated with the master key.
The default value is K/M.

.IP master_key_type
This
.B key type string
represents the master key's key type.

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

.IP iprop_enable
This
.B boolean
("true" or "false") specifies whether incremental database propagation
is enabled.  The default is "false".

.IP iprop_master_ulogsize
This
.B numeric value
specifies the maximum number of log entries to be retained for
incremental propagation.  The maximum value is 2500; default is 1000.

.IP iprop_slave_poll
This
.B delta time string
specfies how often the slave KDC polls for new updates from the
master.  Default is "2m" (that is, two minutes).

.IP supported_enctypes
list of key:salt strings that specifies the default key/salt
combinations of principals for this realm

.IP reject_bad_transit
this
.B boolean
specifies whether or not the list of transited realms for cross-realm
tickets should be checked against the transit path computed from the
realm names and the [capaths] section of its krb5.conf file

.SH FILES 
/usr/local/var/krb5kdc/kdc.conf

.SH SEE ALSO
krb5.conf(5), krb5kdc(8)
