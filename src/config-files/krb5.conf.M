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

.PP 

Each of these sections will be covered in more details in the
following sections.

.SH LIBDEFAULTS SECTION
The following relations are defined in the [libdefaults] section:

.IP default_domain 
This relation identifies the default realm to be used in a client
host's Kerberos activity.

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

.SH FILES 
/etc/krb5.conf

