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
.TH KRB5.CONF 5 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
krb5.conf \- Kerberos configuration file
.SH DESCRIPTION
.I krb5.conf
contains configuration information needed by the Kerberos V5 library.
This includes information describing the default Kerberos realm, and
the location of the Kerberos key distribution centers for known
realms.
.PP
The 
.I krb5.conf
file uses an INI-style format.  Sections are delimited by square
braces; within each section, there are relations where tags can be
assigned to have specific values.  Tags can also contain a subsection, 
which contains further relations or subsections.  A tag can be assigned
to multiple values.   Here is an example of the INI-style format used by 
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

.IP [realms]
Contains subsections keyed by Kerberos realm names which describe
where to find the Kerberos servers for a particular realm, and other
realm-specific information.

.IP [domain_realm]
Contains relations which map subdomains and domain names to Kerberos
realm names.  This is used by programs to determine what realm a host
should be in, given its fully qualified domain name.

.IP [logging]
Contains relations which determine how Kerberos entities are to
perform their logging.

.PP 

Each of these sections will be covered in more details in the
following sections.

.SH LIBDEFAULTS SECTION
The following relations are defined in the [libdefaults] section:

.IP default_domain 
This relation identifies the default realm to be used in a client
host's Kerberos activity.

.IP default_tgs_enctypes
This relation identifies the supported list of session key encryption
types that should be returned by the KDC. The list may be delimited with
commas or whitespace.

.IP clockskew 
This relation sets the maximum allowable amount of clockskew in
seconds that the library will tolerate before assuming that a Kerberos
message is invalid.  The default value is 300 seconds, or five
minutes.

.IP kdc_timesync 
If the value of this relation is non-zero, the library will compute
the difference between the system clock and the time returned by the
KDC and in order to correct for an inaccurate system clock.  This
corrective factor is only used by the Kerberos library.

.SH REALMS SECTION

Each tag in the [realms] section of the file names a Kerberos realm.
The value of the tag is a subsection where the relations in that
subsection define the properties of that particular realm.  For
example:

.sp
.nf
.in +1i
[realms]
	ATHENA.MIT.EDU = {
		kdc = KERBEROS.MIT.EDU
		kdc = KERBEROS-1.MIT.EDU:750
		kdc = KERBEROS-2.MIT.EDU:88
		admin_server = KERBEROS.MIT.EDU
		default_domain = MIT.EDU
		v4_instance_convert = {
			mit = mit.edu
			lithium = lithium.lcs.mit.edu
		}
	}
.in -1i
.fi
.sp

For each realm, the following tags may be specified in the realm's
subsection:

.IP kdc
The value of this relation is the name of a host running a KDC for that realm.
An optional port number (preceded by a colon) may be appended to the
hostname.

.IP admin_server
This relation identifies the host where the administration server is running.
Typically this is the Master Kerberos server.

.IP default_domain
This relation identifies the default domain for which hosts in this
realm are assumed to be in.  This is needed for translating V4 principal names
(which do not contain a domain name) to V5 principal names (which do).  

.IP v4_instance_convert
This subsection allows the administrator to configure exceptions to
the default_domain mapping rule.  It contains V4 instances (the tag
name) which should be translated to some specific hostname (the tag
value) as the second component in a Kerberos V5 principal name.

.SH DOMAIN_REALM SECTION

The [domain_realm] section provides a translation from a hostname to
the Kerberos realm name for the services provided by that host.  
.PP
The tag name can be a hostname, or a domain name, where domain names
are indicated by a prefix of a period ('.') character.  The value of
the relation is the Kerberos realm name for that particular host or domain.
Host names and domain names should be in lower case.
.PP
If no translation entry applies, the host's realm is considered to be
the hostname's domain portion converted to upper case.
For example, the following [domain_realm] section:

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
UCSC.EDU domain into the CATS.UCSC.EDU realm.  ucbvax.berkeley.edu
would be mapped by the default rules to the BERKELEY.EDU realm, while
sage.lcs.mit.edu would be mapped to the LCS.MIT.EDU realm.

.SH LOGGING SECTION

The [logging] section indicates how a particular entity is to perform its
logging.  The relations specified in this section assign one or more values
to the entity name.
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
This value causes the entity's logging messages to go to the specified file.
If the
.B =
form is used, then the file is overwritten.  Otherwise, the file is appended
to.
.IP STDERR
This value causes the entity's logging messages to go to its standard error
stream.
.IP CONSOLE
This value causes the entity's logging messages to go to the console, if
the system supports it.
.IP DEVICE=<devicename>
This causes the entity's logging messages to go to the specified device.
.IP SYSLOG[:<severity>[:<facility>]]
This causes the entity's logging messages to go to the system log.

The
.B severity
argument specifies the default severity of system log messages.  This may
be any of the following severities supported by the
.I syslog(3)
call minus the LOG_ prefix: LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR,
LOG_WARNING, LOG_NOTICE, LOG_INFO, and LOG_DEBUG.
For example, to specify LOG_CRIT severity, one
would use CRIT for
.B severity.

The
.B facility
argument specifies the facility under which the messages are logged.  This
may be any of the following facilities supported by the
.I syslog(3)
call minus the LOG_ prefix: LOG_KERN, LOG_USER, LOG_MAIL, LOG_DAEMON, LOG_AUTH,
LOG_LPR, LOG_NEWS, LOG_UUCP, LOG_CRON, and LOG_LOCAL0 through LOG_LOCAL7.

If no
.B severity
is specified, the default is ERR, and if no
.B facility
is specified, the default is AUTH.
.PP
In the following example, the logging messages from the KDC will go to the
console and to the system log under the facility LOG_DAEMON with default
severity of LOG_INFO; and the logging messages from the administrative server
will be appended to the file /var/adm/kadmin.log and sent to the device
/dev/tty04.
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

.SH FILES 
/etc/krb5.conf

.SH SEE ALSO
syslog(3)
