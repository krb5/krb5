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

-- Message types from protocol spec

-- Some predefined integer values for certain types of fields
MessageType ::=	INTEGER {
	ticket(1), -- XXX RFC draft 3 uses illegal leading capitals
	authenticator(2),
	asReq(10),
	asRep(11),
	tgsReq(12),
	tgsRep(13),
	apReq(14),
	apRep(15),
	safe(20),
	priv(21),
	error(30)
}

AddressType ::= INTEGER {
	internet(2),
	chaosnet(5),
	iso(7),
	xns(6),
	appletalk-ddp(16)
}

-- XXX missing from RFC Draft 3
HostAddress ::= SEQUENCE  {
	addr-type[0]			INTEGER, -- AddressType
	address[1]			OCTET STRING
}

HostAddresses ::=	SEQUENCE OF SEQUENCE {
	addr-type[0]	INTEGER, -- AddressType
	address[1]	OCTET STRING
}

AdType ::=	BIT STRING -- { - - AuthorizationData Type
--	reserved(0),
--	external(1),
--	registered(2),
--	field-type(3-15) - - XXX
--}

AuthorizationData ::=	SEQUENCE OF SEQUENCE {
	ad-type[0]	INTEGER, -- XXX RFC says AdType, should be a 16-bit integer
	ad-data[1]	GeneralString
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
	duplicate-skey(10),
	renewable-ok(27),
	enc-tkt-in-skey(28),
	reuse-skey(29),
	renew(30),
	validate(31)
}

LastReqType ::= 	BIT STRING --{
--	this-server-only(0),
--	interpretation(1-7) - - XXX
--}

LastReq ::=	SEQUENCE OF SEQUENCE {
	lr-type[0]	INTEGER, -- LastReqType
	lr-value[1]	KerberosTime -- XXX RFC draft 3 has trailing ,
}

KerberosTime ::=	GeneralizedTime -- Specifying UTC time zone (Z)

Ticket ::=	[APPLICATION 1] SEQUENCE {
	tkt-vno[0]	INTEGER,
	realm[1]	Realm,
	sname[2]	PrincipalName,
	enc-part[3]	EncryptedData	-- EncTicketPart
}

-- Encrypted part of ticket
-- XXX needs an [APPLICATION x]
EncTicketPart ::=	SEQUENCE {
	flags[0]	TicketFlags,
	key[1]		EncryptionKey,
	crealm[2]	Realm,
	cname[3]	PrincipalName,
	transited[4]	GeneralString,
	authtime[5]	KerberosTime,
	starttime[6]	KerberosTime,
	endtime[7]	KerberosTime,
	renew-till[8]	KerberosTime OPTIONAL,
	caddr[9]	HostAddresses,
	authorization-data[10]	AuthorizationData OPTIONAL
}

-- Unencrypted authenticator
Authenticator ::=	[APPLICATION 2] SEQUENCE  {
	authenticator-vno[0]	AuthenticatorVersion,
	crealm[1]	Realm,
	cname[2]	PrincipalName,
	cksum[3]	Checksum,
	cmsec[4]	INTEGER,
	ctime[5]	KerberosTime
}

AuthenticatorVersion ::= INTEGER {krb5(5)}

-- XXX missing from RFC Draft 3
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
	initial(9),
	duplicate-skey(10)
}

-- XXX RFC Draft 3 needs "ClientName" changed to "PrincipalName"
-- the following two sequences MUST be the same except for the
-- APPLICATION identifier
AS-REQ ::= [APPLICATION 10] SEQUENCE {
	pvno[1]	INTEGER,
	msg-type[2]	INTEGER,
	padata-type[3]	INTEGER,
	padata[4]	OCTET STRING OPTIONAL, -- encoded AP-REQ XXX optional
	req-body[5]	SEQUENCE {
	 kdc-options[0]	KDCOptions,
	 cname[1]	PrincipalName OPTIONAL, -- Used only in AS-REQ
	 realm[2]	Realm, -- Server's realm  Also client's in AS-REQ
	 sname[3]	PrincipalName,
	 from[4]	KerberosTime OPTIONAL,
	 till[5]	KerberosTime,
	 rtime[6]	KerberosTime OPTIONAL,
	 ctime[7]	KerberosTime,
	 nonce[8]	INTEGER,
	 etype[9]	INTEGER, -- EncryptionType
	 addresses[10]	HostAddresses OPTIONAL,
	 authorization-data[11]	AuthorizationData OPTIONAL,
	 additional-tickets[12]	SEQUENCE OF Ticket OPTIONAL
	}
}
TGS-REQ ::= [APPLICATION 12] SEQUENCE {
	pvno[1]	INTEGER,
	msg-type[2]	INTEGER,
	padata-type[3]	INTEGER,
	padata[4]	OCTET STRING, -- encoded AP-REQ
	req-body[5]	SEQUENCE {
	 kdc-options[0]	KDCOptions,
	 cname[1]	PrincipalName OPTIONAL, -- Used only in AS-REQ
	 realm[2]	Realm, -- Server's realm  Also client's in AS-REQ
	 sname[3]	PrincipalName,
	 from[4]	KerberosTime OPTIONAL,
	 till[5]	KerberosTime,
	 rtime[6]	KerberosTime OPTIONAL,
	 ctime[7]	KerberosTime,
	 nonce[8]	INTEGER,
	 etype[9]	INTEGER, -- EncryptionType
	 addresses[10]	HostAddresses OPTIONAL,
	 authorization-data[11]	AuthorizationData OPTIONAL,
	 additional-tickets[12]	SEQUENCE OF Ticket OPTIONAL
	}
}
-- the preceding two sequences MUST be the same except for the
-- APPLICATION identifier

-- the following two sequences MUST be the same except for the
-- APPLICATION identifier
AS-REP ::= [APPLICATION 11] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER, -- MessageType
	crealm[2]			Realm,
	cname[3]			PrincipalName,
	ticket[4]			Ticket,		-- Ticket
	enc-part[5]			EncryptedData	-- EncKDCRepPart
}
TGS-REP ::= [APPLICATION 13] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER, -- MessageType
	crealm[2]			Realm,
	cname[3]			PrincipalName,
	ticket[4]			Ticket,		-- Ticket
	enc-part[5]			EncryptedData	-- EncKDCRepPart
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
	realm[9]	Realm, -- XXX should be srealm
	sname[10]	PrincipalName,
	caddr[11]	HostAddresses
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
	realm[9]	Realm, -- XXX should be srealm
	sname[10]	PrincipalName,
	caddr[11]	HostAddresses
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

-- XXX These appear twice in the draft 3 RFC
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
	cmsec[1]			INTEGER
}

KRB-SAFE ::= [APPLICATION 20] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	user-data[2]			OCTET STRING,
	timestamp[3]			KerberosTime,
	msec[4]				INTEGER,
	s-address[5]			HostAddress,	-- sender's addr
	r-address[6]			HostAddress,	-- recip's addr
	cksum[7]			Checksum			
}

KRB-PRIV ::=	[APPLICATION 21] SEQUENCE {
	pvno[0]		INTEGER,
	msg-type[1]	INTEGER,
	enc-part[3]	EncryptedData	-- EncKrbPrivPart
}

EncKrbPrivPart ::=	[APPLICATION 28] SEQUENCE {
	user-data[0]	OCTET STRING,
	timestamp[1]	KerberosTime,
	msec[2]		INTEGER,
	s-address[3]	HostAddress,	-- sender's addr
	r-address[4]	HostAddress	-- recip's addr
}

KRB-ERROR ::=	[APPLICATION 30] SEQUENCE {
	pvno[0]		INTEGER,
	msg-type[1]	INTEGER,
	ctime[2]	KerberosTime OPTIONAL,
	cmsec[3]	INTEGER OPTIONAL,
	stime[4]	KerberosTime,
	smsec[5]	INTEGER,
	error-code[6]	INTEGER,
	crealm[7]	Realm OPTIONAL,
	cname[8]	PrincipalName OPTIONAL,
	realm[9]	Realm, -- Correct realm
	sname[10]	PrincipalName, -- Correct name
	e-text[11]	GeneralString OPTIONAL, -- XXX should be optional
	e-data[12]	OCTET STRING OPTIONAL
}

EncryptedData ::=	SEQUENCE {
	etype[0]	INTEGER, -- EncryptionType
	kvno[1]		INTEGER OPTIONAL,
	cipher[2]	OCTET STRING -- CipherText
}

EncryptionType ::=	INTEGER {
	null(0),
	des-cbc-crc(1),
	lucifer-cbc-crc(2)
}

EncryptionKey ::= SEQUENCE {
	keytype[0]			INTEGER, -- KeyType
	keyvalue[1]			OCTET STRING
}

KeyType ::=	INTEGER {
	null(0),
	des(1),
	lucifer(2)
}

Checksum ::= SEQUENCE {
	cksumtype[0]			INTEGER, -- ChecksumType
	checksum[1]			OCTET STRING
}

ChecksumType ::=	INTEGER {
	crc32(1),
	rsa-md4(2),
	rsa-md4-des(3),
	snefru(4),
	des-mac(5)
}

END
