-- $Source$
-- $Author$
-- $Id$
--
-- Copyright 1989 by the Massachusetts Institute of Technology.
--
-- For copying and distribution information, please see the file
-- <krb5/copyright.h>.
--
-- ASN.1 definitions for the kerberos network objects
--

KRB5 DEFINITIONS ::=
BEGIN

-- the order of stuff in this file matches the order in the draft RFC

Realm ::= GeneralString
PrincipalName ::= SEQUENCE OF GeneralString

HostAddress ::= SEQUENCE  {
	addr-type[0]			INTEGER,
	address[1]			OCTET STRING
}

HostAddresses ::=	SEQUENCE OF SEQUENCE {
	addr-type[0]	INTEGER,
	address[1]	OCTET STRING
}

AuthorizationData ::=	SEQUENCE OF SEQUENCE {
	ad-type[0]	INTEGER,
	ad-data[1]	OCTET STRING
}

KDCOptions ::= BIT STRING {
	reserved(0),
	forwardable(1),
	forwarded(2),
	proxiable(3),
	proxy(4),
	allow-postdate(5),
	postdated(6),
	unused7(7),
	renewable(8),
	unused9(9),
	renewable-ok(27),
	enc-tkt-in-skey(28),
	renew(30),
	validate(31)
}

LastReq ::=	SEQUENCE OF SEQUENCE {
	lr-type[0]	INTEGER,
	lr-value[1]	KerberosTime
}

KerberosTime ::=	GeneralizedTime -- Specifying UTC time zone (Z)

Ticket ::=	[APPLICATION 1] SEQUENCE {
	tkt-vno[0]	INTEGER,
	realm[1]	Realm,
	sname[2]	PrincipalName,
	enc-part[3]	EncryptedData	-- EncTicketPart
}

TransitedEncoding ::= SEQUENCE {
	tr-type[0]	INTEGER, -- Only supported value is 1 == DOMAIN-COMPRESS
	contents[1]	OCTET STRING
}

-- Encrypted part of ticket
EncTicketPart ::=	[APPLICATION 3] SEQUENCE {
	flags[0]	TicketFlags,
	key[1]		EncryptionKey,
	crealm[2]	Realm,
	cname[3]	PrincipalName,
	transited[4]	TransitedEncoding,
	authtime[5]	KerberosTime,
	starttime[6]	KerberosTime OPTIONAL,
	endtime[7]	KerberosTime,
	renew-till[8]	KerberosTime OPTIONAL,
	caddr[9]	HostAddresses,
	authorization-data[10]	AuthorizationData OPTIONAL
}

-- Unencrypted authenticator
Authenticator ::=	[APPLICATION 2] SEQUENCE  {
	authenticator-vno[0]	INTEGER,
	crealm[1]	Realm,
	cname[2]	PrincipalName,
	cksum[3]	Checksum OPTIONAL,
	cusec[4]	INTEGER,
	ctime[5]	KerberosTime,
	subkey[6]	EncryptionKey OPTIONAL,
	seq-number[7]	INTEGER OPTIONAL
}

TicketFlags ::= BIT STRING {
	reserved(0),
	forwardable(1),
	forwarded(2),
	proxiable(3),
	proxy(4),
	may-postdate(5),
	postdated(6),
	invalid(7),
	renewable(8),
	initial(9)
}

-- the following two sequences MUST be the same except for the
-- APPLICATION identifier
AS-REQ ::= [APPLICATION 10] SEQUENCE {
	pvno[1]	INTEGER,
	msg-type[2]	INTEGER,
	padata[3]	PA-DATA OPTIONAL,
	req-body[4]	KDC-REQ-BODY
}
TGS-REQ ::= [APPLICATION 12] SEQUENCE {
	pvno[1]	INTEGER,
	msg-type[2]	INTEGER,
	padata[3]	PA-DATA OPTIONAL, -- encoded AP-REQ, not optional
	req-body[4]	KDC-REQ-BODY
}
-- the preceding two sequences MUST be the same except for the
-- APPLICATION identifier

PA-DATA ::=	SEQUENCE OF SEQUENCE {
	padata-type[1]	INTEGER,
	pa-data[2]	OCTET STRING -- might be encoded AP-REQ
}

KDC-REQ-BODY ::=	SEQUENCE {
	 kdc-options[0]	KDCOptions,
	 cname[1]	PrincipalName OPTIONAL, -- Used only in AS-REQ
	 realm[2]	Realm, -- Server's realm  Also client's in AS-REQ
	 sname[3]	PrincipalName,
	 from[4]	KerberosTime OPTIONAL,
	 till[5]	KerberosTime,
	 rtime[6]	KerberosTime OPTIONAL,
	 nonce[7]	INTEGER,
	 etype[8]	SEQUENCE OF INTEGER, -- EncryptionType, in preference order
	 addresses[9]	HostAddresses OPTIONAL,
	 authorization-data[10]	EncryptedData OPTIONAL, -- AuthorizationData
	 additional-tickets[11]	SEQUENCE OF Ticket OPTIONAL
}

-- the following two sequences MUST be the same except for the
-- APPLICATION identifier
AS-REP ::= [APPLICATION 11] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	padata[2]			PA-DATA OPTIONAL,
	crealm[3]			Realm,
	cname[4]			PrincipalName,
	ticket[5]			Ticket,		-- Ticket
	enc-part[6]			EncryptedData	-- EncKDCRepPart
}
TGS-REP ::= [APPLICATION 13] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	padata[2]			PA-DATA OPTIONAL,
	crealm[3]			Realm,
	cname[4]			PrincipalName,
	ticket[5]			Ticket,		-- Ticket
	enc-part[6]			EncryptedData	-- EncKDCRepPart
}
-- the preceding two sequences MUST be the same except for the
-- APPLICATION identifier

-- the following two sequences MUST be the same except for the
-- APPLICATION identifier
EncASRepPart ::=	[APPLICATION 25] SEQUENCE {
	key[0]	EncryptionKey,
	last-req[1]	LastReq,
	nonce[2]	INTEGER,
	key-expiration[3]	KerberosTime OPTIONAL,
	flags[4]	TicketFlags,
	authtime[5]	KerberosTime,
	starttime[6]	KerberosTime OPTIONAL,
	endtime[7]	KerberosTime,
	renew-till[8]	KerberosTime OPTIONAL,
	srealm[9]	Realm,
	sname[10]	PrincipalName,
	caddr[11]	HostAddresses OPTIONAL
}
EncTGSRepPart ::=	[APPLICATION 26] SEQUENCE {
	key[0]	EncryptionKey,
	last-req[1]	LastReq,
	nonce[2]	INTEGER,
	key-expiration[3]	KerberosTime OPTIONAL,
	flags[4]	TicketFlags,
	authtime[5]	KerberosTime,
	starttime[6]	KerberosTime OPTIONAL,
	endtime[7]	KerberosTime,
	renew-till[8]	KerberosTime OPTIONAL,
	srealm[9]	Realm,
	sname[10]	PrincipalName,
	caddr[11]	HostAddresses OPTIONAL
}
-- the preceding two sequences MUST be the same except for the
-- APPLICATION identifier

AP-REQ ::= [APPLICATION 14] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	ap-options[2]			APOptions,
	ticket[3]			Ticket,
	authenticator[4]		EncryptedData	-- Authenticator
}

APOptions ::= BIT STRING {
	reserved(0),
	use-session-key(1),
	mutual-required(2)
}

AP-REP ::= [APPLICATION 15] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	enc-part[2]			EncryptedData	-- EncAPRepPart
}

EncAPRepPart ::= [APPLICATION 27] SEQUENCE {
	ctime[0]			KerberosTime,
	cusec[1]			INTEGER,
	subkey[2]			EncryptionKey OPTIONAL,
	seq-number[3]			INTEGER OPTIONAL
}

KRB-SAFE ::= [APPLICATION 20] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	safe-body[2]			KRB-SAFE-BODY,
	cksum[3]			Checksum			
}

KRB-SAFE-BODY ::=	SEQUENCE {
	user-data[0]			OCTET STRING,
	timestamp[1]			KerberosTime OPTIONAL,
	usec[2]				INTEGER OPTIONAL,
	seq-number[3]			INTEGER OPTIONAL,
	s-address[4]			HostAddress,	-- sender's addr
	r-address[5]			HostAddress OPTIONAL -- recip's addr
}

KRB-PRIV ::=	[APPLICATION 21] SEQUENCE {
	pvno[0]		INTEGER,
	msg-type[1]	INTEGER,
	enc-part[3]	EncryptedData	-- EncKrbPrivPart
}

EncKrbPrivPart ::=	[APPLICATION 28] SEQUENCE {
	user-data[0]	OCTET STRING,
	timestamp[1]	KerberosTime OPTIONAL,
	usec[2]		INTEGER OPTIONAL,
	seq-number[3]	INTEGER OPTIONAL,
	s-address[4]	HostAddress,	-- sender's addr
	r-address[5]	HostAddress OPTIONAL	-- recip's addr
}

KRB-ERROR ::=	[APPLICATION 30] SEQUENCE {
	pvno[0]		INTEGER,
	msg-type[1]	INTEGER,
	ctime[2]	KerberosTime OPTIONAL,
	cusec[3]	INTEGER OPTIONAL,
	stime[4]	KerberosTime,
	susec[5]	INTEGER,
	error-code[6]	INTEGER,
	crealm[7]	Realm OPTIONAL,
	cname[8]	PrincipalName OPTIONAL,
	realm[9]	Realm, -- Correct realm
	sname[10]	PrincipalName, -- Correct name
	e-text[11]	GeneralString OPTIONAL,
	e-data[12]	OCTET STRING OPTIONAL
}

EncryptedData ::=	SEQUENCE {
	etype[0]	INTEGER, -- EncryptionType
	kvno[1]		INTEGER OPTIONAL,
	cipher[2]	OCTET STRING -- CipherText
}

EncryptionKey ::= SEQUENCE {
	keytype[0]			INTEGER,
	keyvalue[1]			OCTET STRING
}

Checksum ::= SEQUENCE {
	cksumtype[0]			INTEGER,
	checksum[1]			OCTET STRING
}

METHOD-DATA ::= SEQUENCE {
	method-type[0]	INTEGER,
	method-data[1]	OCTET STRING OPTIONAL
}
END
