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
.\" permission.  Furthermore if you modify this software you must label
.\" your software as modified software and not distribute it in such a
.\" fashion that it might be confused with the original M.I.T. software.
.\" M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" "
.TH KRB5.CONF 5
.SH NAME
krb5.conf \- Kerberos configuration file
.SH DESCRIPTION
.I krb5.conf
contains configuration information needed by the Kerberos V5 library.
This includes information describing the default Kerberos realm, and the
location of the Kerberos key distribution centers for known realms.
.PP
The 
.I krb5.conf
file uses an INI-style format.  Sections are delimited by square braces;
within each section, there are relations where tags can be assigned to
have specific values.  Tags can also contain a subsection, which
contains further relations or subsections.  A tag can be assigned to
multiple values.  Here is an example of the INI-style format used by
.IR krb5.conf :

.sp
.nf
.in +1i
[section1]
	tag1 = value_a
	tag1 = value_b
	tag2 = value_c

[section 2]
	tag3 = {
		subtag1 = subtag_value_a
		subtag1 = subtag_value_b
		subtag2 = subtag_value_c
	}
	tag4 = {
		subtag1 = subtag_value_d
		subtag2 = subtag_value_e
	}
.in -1i
.fi
.sp

.PP
The following sections are currently used in the 
.I krb5.conf
file:
.IP [libdefaults]
Contains various default values used by the Kerberos V5 library.

.IP [login]
Contains default values used by the Kerberos V5 login program,
.IR login.krb5 (8).

.IP [appdefaults]
Contains default values that can be used by Kerberos V5 applications.

.IP [realms]
Contains subsections keyed by Kerberos realm names which describe where
to find the Kerberos servers for a particular realm, and other
realm-specific information.

.IP [domain_realm]
Contains relations which map subdomains and domain names to Kerberos
realm names.  This is used by programs to determine what realm a host
should be in, given its fully qualified domain name.

.IP [logging]
Contains relations which determine how Kerberos entities are to perform
their logging.

.IP [capaths]
Contains the authentication paths used with non-hierarchical
cross-realm. Entries in the section are used by the client to determine
the intermediate realms which may be used in cross-realm
authentication. It is also used by the end-service when checking the
transited field for trusted intermediate realms.
.PP 
Each of these sections will be covered in more details in the following
sections.
.SH LIBDEFAULTS SECTION
The following relations are defined in the [libdefaults] section:

.IP default_keytab_name
This relation specifies the default keytab name to be used by
application severs such as telnetd and rlogind.  The default is
"/etc/krb5.keytab".  This formerly defaulted to "/etc/v5srvtab", but
was changed to the current value.

.IP default_realm
This relation identifies the default realm to be used in a client host's
Kerberos activity.

.IP default_tgs_enctypes
This relation identifies the supported list of session key encryption
types that should be returned by the KDC. The list may be delimited with
commas or whitespace.

.IP default_tkt_enctypes
This relation identifies the supported list of session key encryption
types that should be requested by the client, in the same format.

.IP permitted_enctypes
This relation identifies the permitted list of session key encryption
types.

.IP clockskew 
This relation sets the maximum allowable amount of clockskew in seconds
that the library will tolerate before assuming that a Kerberos message
is invalid.  The default value is 300 seconds, or five minutes.

.IP kdc_timesync 
If the value of this relation is non-zero (the default), the library
will compute the difference between the system clock and the time
returned by the KDC and in order to correct for an inaccurate system
clock.  This corrective factor is only used by the Kerberos library.

.IP kdc_req_checksum_type
For compatability with DCE security servers which do not support the
default CKSUMTYPE_RSA_MD5 used by this version of Kerberos. Use a value
of 2 to use the CKSUMTYPE_RSA_MD4 instead. This applies to DCE 1.1 and
earlier.

.IP ap_req_checksum_type 
This allows you to set the checksum type used in the authenticator of
KRB_AP_REQ messages.  The default value for this type is
CKSUMTYPE_RSA_MD5.  For compatibility with applications linked against
DCE version 1.1 or earlier Kerberos libraries, use a value of 2 to use
the CKSUMTYPE_RSA_MD4
instead.

.IP safe_checksum_type 
This allows you to set the preferred keyed-checksum type for use in KRB_SAFE
messages.  The default value for this type is CKSUMTYPE_RSA_MD5_DES.
For compatibility with applications linked against DCE version 1.1 or
earlier Kerberos
libraries, use a value of 3 to use the CKSUMTYPE_RSA_MD4_DES
instead.  This field is ignored when its value is incompatible with
the session key type.

.IP ccache_type
User this parameter on systems which are DCE clients, to specify the
type of cache to be created by kinit, or when forwarded tickets are
received. DCE and Kerberos can share the cache, but some versions of DCE
do not support the default cache as created by this version of
Kerberos. Use a value of 1 on DCE 1.0.3a systems, and a value of 2 on
DCE 1.1 systems.

.IP krb4_srvtab 
Specifies the location of the Kerberos V4 srvtab file.  Default is
"/etc/srvtab".

.IP krb4_config
Specifies the location of hte Kerberos V4 configuration file.  Default
is "/etc/krb.conf".

.IP krb4_realms
Specifies the location of the Kerberos V4 domain/realm translation
file.  Default is "/etc/krb.realms".

.IP dns_lookup_kdc
Indicate whether DNS SRV records shoud be used to locate the KDCs and 
other servers for a realm, if they are not listed in the information 
for the realm.  The default is to use these records.

.IP dns_lookup_realm
Indicate whether DNS TXT records should be used to determine the Kerberos
realm of a host.  The default is not to use these records.

.IP dns_fallback
General flag controlling the use of DNS for Kerberos information.  If both
of the preceding options are specified, this option has no effect.

.IP extra_addresses
This allows a computer to use multiple local addresses, in order to
allow Kerberos to work in a network that uses NATs.  The addresses should
be in a comma-separated list.

.IP udp_preference_limit
When sending a message to the KDC, the library will try using TCP
before UDP if the size of the message is above "udp_preference_list".
If the message is smaller than "udp_preference_list", then UDP will be
tried before TCP.  Regardless of the size, both protocols will be
tried if the first attempt fails.

.IP verify_ap_req_nofail
If this flag is set, then an attempt to get initial credentials will
fail if the client machine does not have a keytab.  The default for the
flag is false.

.IP renew_lifetime
The value of this tag is the default renewable lifetime for initial
tickets.  The default value for the tag is 0.

.IP noaddresses
Setting this flag causes the initial Kerberos ticket to be addressless.
The default for the flag is true.

.IP forwardable
If this flag is set, initial tickets by default will be forwardable.
The default value for this flag is false.

.IP proxiable
If this flag is set, initial tickets by default will be proxiable.
The default value for this flag is false.

.SH APPDEFAULTS SECTION

Each tag in the [appdefaults] section names a Kerberos V5 application
or an option that is used by some Kerberos V5 application[s].  The
four ways that you can set values for options are as follows, in
decreasing order of precedence:

.sp
.nf
.in +1i
#1) 	
	application = {
		realm1 = {
			option = value
		}
		realm2 = {
			option = value
		}
	}
#2) 	
	application = {
		option1 = value
		option2 = value
	}
#3)	
	realm = {
		option = value
	}
#4)	
	option = value
.in -1in
.fi
.sp

.SH LOGIN SECTION
The [login] section is used to configure the behavior of the Kerberos V5
login program,
.IR login.krb5 (8).
Refer to the manual entry for
.I login.krb5
for a description of the relations allowed in this section.
.SH REALMS SECTION
Each tag in the [realms] section of the file names a Kerberos realm.
The value of the tag is a subsection where the relations in that
subsection define the properties of that particular realm.  For example:

.sp
.nf
.in +1i
[realms]
	ATHENA.MIT.EDU = {
		admin_server = KERBEROS.MIT.EDU
		default_domain = MIT.EDU
		v4_instance_convert = {
			mit = mit.edu
			lithium = lithium.lcs.mit.edu
		}
		v4_realm = LCS.MIT.EDU
	}
.in -1i
.fi
.sp

For each realm, the following tags may be specified in the realm's
subsection:

.IP kdc
The value of this relation is the name of a host running a KDC for that
realm.  An optional port number (preceded by a colon) may be appended to
the hostname.  This tag should generally be used only if the realm
administrator has not made the information available through DNS.

.IP admin_server
This relation identifies the host where the administration server is
running.  Typically this is the Master Kerberos server.

.IP default_domain
This relation identifies the default domain for which hosts in this
realm are assumed to be in.  This is needed for translating V4 principal
names (which do not contain a domain name) to V5 principal names (which
do).

.IP v4_instance_convert
This subsection allows the administrator to configure exceptions to the
default_domain mapping rule.  It contains V4 instances (the tag name)
which should be translated to some specific hostname (the tag value) as
the second component in a Kerberos V5 principal name.

.IP v4_realm
This relation is used by the krb524 library routines when converting 
a V5 principal name to a V4 principal name. It is used when V4 realm
name and the V5 realm are not the same, but still share the same 
principal names and passwords. The tag value is the Kerberos V4 realm 
name. 

.IP auth_to_local_names
This subsection allows you to set explicit mappings from principal
names to local user names.  The tag is the mapping name, and the value
is the corresponding local user name.

.IP auth_to_local
This tag allows you to set a general rule for mapping principal names
to local user names.  It will be used if there is not an explicit
mapping for the principal name that is being translated.  The possible
values are:

.in +.5i
DB:<filename>
.in +.5i
The principal will be looked up in the database <filename>.
Support for this is not currently compiled in by default.
.in -.5in
RULE:<exp>
.in +.5i
The local name will be formulated from <exp>.
.in -.5i
DEFAULT
.in +.5i
The principal name will be used as the local name.  If the
principal has more than one component or is not in the default
realm, this rule is not applicable and the conversion will fail.
.in -1i

.SH DOMAIN_REALM SECTION

The [domain_realm] section provides a translation from a hostname to the
Kerberos realm name for the services provided by that host.
.PP
The tag name can be a hostname, or a domain name, where domain names are
indicated by a prefix of a period ('.') character.  The value of the
relation is the Kerberos realm name for that particular host or domain.
Host names and domain names should be in lower case.
.PP
If no translation entry applies, the host's realm is considered to be
the hostname's domain portion converted to upper case.  For example, the
following [domain_realm] section:

.sp
.nf
.in +1i
[domain_realm]
	.mit.edu = ATHENA.MIT.EDU
	mit.edu = ATHENA.MIT.EDU 
	dodo.mit.edu = SMS_TEST.MIT.EDU
	.ucsc.edu = CATS.UCSC.EDU
.in -1i
.fi
.sp
maps dodo.mit.edu into the SMS_TEST.MIT.EDU realm, all other hosts in
the MIT.EDU domain to the ATHENA.MIT.EDU realm, and all hosts in the
UCSC.EDU domain into the CATS.UCSC.EDU realm.  ucbvax.berkeley.edu would
be mapped by the default rules to the BERKELEY.EDU realm, while
sage.lcs.mit.edu would be mapped to the LCS.MIT.EDU realm.

.SH LOGGING SECTION

The [logging] section indicates how a particular entity is to perform
its logging.  The relations specified in this section assign one or more
values to the entity name.
.PP
Currently, the following entities are used:
.IP kdc
These entries specify how the KDC is to perform its logging.
.IP admin_server
These entries specify how the administrative server is to perform its logging.
.IP default
These entries specify how to perform logging in the absence of explicit
specifications otherwise.
.PP
Values are of the following forms:
.IP FILE=<filename>
.IP FILE:<filename>
This value causes the entity's logging messages to go to the specified
file.  If the
.B =
form is used, then the file is overwritten.  Otherwise, the file is
appended to.
.IP STDERR
This value causes the entity's logging messages to go to its standard
error stream.
.IP CONSOLE
This value causes the entity's logging messages to go to the console, if
the system supports it.
.IP DEVICE=<devicename>
This causes the entity's logging messages to go to the specified device.
.IP SYSLOG[:<severity>[:<facility>]]
This causes the entity's logging messages to go to the system log.

The
.B severity
argument specifies the default severity of system log messages.  This
may be any of the following severities supported by the
.I syslog(3)
call minus the LOG_ prefix: LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR,
LOG_WARNING, LOG_NOTICE, LOG_INFO, and LOG_DEBUG.  For example, to
specify LOG_CRIT severity, one would use CRIT for
.B severity.

The
.B facility
argument specifies the facility under which the messages are logged.
This may be any of the following facilities supported by the
.I syslog(3)
call minus the LOG_ prefix: LOG_KERN, LOG_USER, LOG_MAIL, LOG_DAEMON,
LOG_AUTH, LOG_LPR, LOG_NEWS, LOG_UUCP, LOG_CRON, and LOG_LOCAL0 through
LOG_LOCAL7.

If no
.B severity
is specified, the default is ERR, and if no
.B facility
is specified, the default is AUTH.
.PP
In the following example, the logging messages from the KDC will go to
the console and to the system log under the facility LOG_DAEMON with
default severity of LOG_INFO; and the logging messages from the
administrative server will be appended to the file /var/adm/kadmin.log
and sent to the device /dev/tty04.
.sp
.nf
.in +1i
[logging]
	kdc = CONSOLE
	kdc = SYSLOG:INFO:DAEMON
	admin_server = FILE:/var/adm/kadmin.log
	admin_server = DEVICE=/dev/tty04
.in -1i
.fi
.sp

.SH CAPATHS SECTION

Cross-realm authentication is typically organized hierarchically.  This
hierarchy is based on the name of the realm, which thus imposes
restrictions on the choice of realm names, and on who may participate in
a cross-realm authentication. A non hierarchical orgization may be used,
but requires a database to construct the authentication paths between
the realms. This section defines that database.
.PP
A client will use this section to find the authentication path between
its realm and the realm of the server. The server will use this section
to verify the authentication path used be the client, by checking the
transited field of the received ticket.
.PP
There is a tag name for each participating realm, and each tag has
subtags for each of the realms. The value of the subtags is an
intermediate realm which may participate in the cross-realm
authentication. The subtags may be repeated if there is more then one
intermediate realm. A value of "." means that the two realms share keys
directly, and no intermediate realms should be allowed to participate.
.PP
There are n**2 possible entries in this table, but only those entries
which will be needed on the client or the server need to be present. The
client needs a tag for its local realm, with subtags for all the realms
of servers it will need to authenticate with.  A server needs a tag for
each realm of the clients it will serve.
.PP
For example, ANL.GOV, PNL.GOV, and NERSC.GOV all wish to use the ES.NET
realm as an intermediate realm. ANL has a sub realm of TEST.ANL.GOV
which will authenticate with NERSC.GOV but not PNL.GOV.  The [capath]
section for ANL.GOV systems would look like this:
.sp
.nf
.in +1i
[capaths]
	ANL.GOV = {
		TEST.ANL.GOV = .
		PNL.GOV = ES.NET
		NERSC.GOV = ES.NET
		ES.NET = .
	}
	TEST.ANL.GOV = {
		ANL.GOV = .
	}
	PNL.GOV = {
		ANL.GOV = ES.NET
	}
	NERSC.GOV = {
		ANL.GOV = ES.NET
	}
	ES.NET = {
		ANL.GOV = .
	}
.in -1i
.fi
.sp
The [capath] section of the configuration file used on NERSC.GOV systems
would look like this:
.sp
.nf
.in +1i
[capaths]
	NERSC.GOV = {
		ANL.GOV = ES.NET
		TEST.ANL.GOV = ES.NET
		TEST.ANL.GOV = ANL.GOV
		PNL.GOV = ES.NET
		ES.NET = .
	}
	ANL.GOV = {
		NERSC.GOV = ES.NET
	}
	PNL.GOV = {
		NERSC.GOV = ES.NET
	}
	ES.NET = {
		NERSC.GOV = .
	}
	TEST.ANL.GOV = {
		NERSC.GOV = ANL.GOV
		NERSC.GOV = ES.NET
	}
.in -1i
.fi
.sp
In the above examples, the ordering is not important, except when the
same subtag name is used more then once. The client will use this to
determing the path. (It is not important to the server, since the
transited field is not sorted.)
.PP
If this section is not present, or if the client or server cannot find a
client/server path, then normal hierarchical orginization is assumed.
.PP
This feature is not currently supported by DCE. DCE security servers can
be used with Kerberized clients and servers, but versions prior to DCE
1.1 did not fill in the transited field, and should be used with
caution.
.SH FILES 
/etc/krb5.conf
.SH SEE ALSO
syslog(3)
