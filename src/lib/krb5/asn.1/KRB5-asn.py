-- $Source$
-- $Author$
-- $Id$
--
-- Copyright 1989 by the Massachusetts Institute of Technology.
--
-- For copying and distribution information, please see the file
-- <krb5/mit-copyright.h>.
--
-- ASN.1 definitions for the kerberos network objects
--

KRB5 DEFINITIONS ::=
BEGIN

-- Define "better" names

Realm ::= GeneralString
PrincipalName ::= SEQUENCE OF GeneralString
EncryptedData ::= OCTET STRING

-- Message types from protocol spec

-- Some predefined integer values for certain types of fields
MessageType ::= INTEGER {
	asReq(2),
	asRep(4),
	apReq(6),
	tgsReq(8),
	apRep(10),
	tgsRep(12),
	safe(14),
	priv(16),
	error(32)
}

AddressType ::= INTEGER {
	internet(2),
	chaosnet(5),
	iso(7),
	xns(6),
	appletalk-ddp(16)
}

KeyType ::= INTEGER {
	null(0),
	des(1),
	lucifer(2)
}

EncryptionType ::= INTEGER {
	null(0),
	des-cbc(1),
	lucifer-cbc(2)
}

ChecksumType ::= INTEGER {
	crc(1),
	-- xxx(2),
	snefru(3),
	des-mac(4)
}

-- EncryptionKey 
EncryptionKey ::= SEQUENCE {
	keytype[0]			INTEGER, -- KeyType
	session[1]			OCTET STRING
}

Checksum ::= SEQUENCE {
	cksumtype[0]			INTEGER, -- ChecksumType
	checksum[1]			OCTET STRING
}

-- Unencrypted authenticator
Authenticator ::= SEQUENCE  {
	authenticator-vno[0]		AuthenticatorVersion,
	crealm[1]			Realm,
	cname[2]			PrincipalName,
	cksum[3]			Checksum,
	cmsec[4]			INTEGER,
	ctime[5]			UTCTime
}

AuthenticatorVersion ::= INTEGER {krb5(5)}

-- Encrypted part of ticket
EncTicketPart ::= SEQUENCE {
	flags[0]			TicketFlags,
	key[1]				EncryptionKey,
	crealm[2]			Realm,
	cname[3]			PrincipalName,
	transited[4]			GeneralString,
	authtime[5]			UTCTime,
	starttime[6]			UTCTime,
	endtime[7]			UTCTime,
	renew-till[8]			UTCTime OPTIONAL,
	caddr[9]			HostAddresses,
	authorization-data[10]		AuthorizationData OPTIONAL
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
	initial(9),
	duplicate-skey(10)
}

HostAddresses ::= SEQUENCE OF SEQUENCE {
	addr-type[0]			INTEGER, -- AddressType
	address[1]			OCTET STRING
}

AuthorizationData ::= SEQUENCE OF SEQUENCE {
	ad-type[0]			INTEGER,
	ad-data[1]			GeneralString
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

Ticket ::= SEQUENCE {
	tkt-vno[0]			INTEGER,
	srealm[1]			Realm,
	sname[2]			PrincipalName,
	etype[3]			INTEGER, -- EncryptionType
	skvno[4]			INTEGER,
	enc-part[5]			EncryptedData	-- EncTicketPart
}

AS-REQ ::= [APPLICATION 0] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	kdc-options[2]			KDCOptions,
	ctime[3]			UTCTime,
	from[4]				UTCTime,
	till[5]				UTCTime,
	rtime[6]			UTCTime OPTIONAL,
	etype[7]			INTEGER, -- EncryptionType
	crealm[8]			Realm,
	cname[9]			PrincipalName,
	addresses[10]			HostAddresses,
	sname[11]			PrincipalName
}

KDC-REP ::= [APPLICATION 1] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	crealm[2]			Realm,
	cname[3]			PrincipalName,
	etype[4]			INTEGER, -- EncryptionType
	ckvno[5]			INTEGER,
	ticket[6]			Ticket,		-- Ticket
	enc-part[7]			EncryptedData	-- EncKDCRepPart
}

EncKDCRepPart ::= SEQUENCE {
	key[0]				EncryptionKey,
	last-req[1]			LastReq,
	ctime[2]			UTCTime,
	key-exp[4]			UTCTime,
	flags[5]			TicketFlags,
	authtime[3]			UTCTime,	-- also known as ktime
	starttime[6]			UTCTime,
	endtime[7]			UTCTime,
	renew-till[8]			UTCTime OPTIONAL,
	srealm[9]			Realm,
	sname[10]			PrincipalName,
	caddr[11]			HostAddresses
}

KRB-ERROR ::= [APPLICATION 2] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	ctime[2]			UTCTime,
	cmsec[3]			INTEGER,
	stime[4]			UTCTime,
	smsec[5]			INTEGER,
	error[6]			INTEGER,
	crealm[7]			Realm,
	cname[8]			PrincipalName,
	srealm[9]			Realm,
	sname[10]			PrincipalName,
	e-text[11]			GeneralString
}

LastReq ::= SEQUENCE OF SEQUENCE {
	lr-type[0]			INTEGER,
	lr-value[1]			INTEGER
}

AP-REQ ::= [APPLICATION 3] SEQUENCE {
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

AP-REP ::= [APPLICATION 4] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	enc-part[2]			EncryptedData	-- EncAPRepPart
}

EncAPRepPart ::= SEQUENCE {
	ctime[0]			UTCTime,
	cmsec[1]			INTEGER
}

TGS-REQ ::= [APPLICATION 5] SEQUENCE {
	header[0]			AP-REQ,
	pvno[1]				INTEGER,
	msg-type[2]			INTEGER,
	kdc-options[3]			KDCOptions,
	from[4]				UTCTime,
	till[5]				UTCTime,
	rtime[6]			UTCTime OPTIONAL,
	ctime[7]			UTCTime,
	etype[8]			INTEGER, -- EncryptionType
	sname[9]			PrincipalName,
	addresses[10]			HostAddresses,
	enc-part[11]			EncryptedData OPTIONAL -- EncTgsReqPart
}

EncTgsReqPart ::= SEQUENCE {
	authorization-data[0]		AuthorizationData OPTIONAL,
	second-ticket[1]		Ticket OPTIONAL
}

KRB-SAFE ::= [APPLICATION 6] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	user-data[2]			OCTET STRING,
	timestamp[3]			UTCTime,
	msec[4]				INTEGER,
	addresses[5]			HostAddresses,
	checksum[6]			Checksum			
}

KRB-PRIV ::= [APPLICATION 7] SEQUENCE {
	pvno[0]				INTEGER,
	msg-type[1]			INTEGER,
	etype[2]			INTEGER, -- EncryptionType
	enc-part[3]			EncryptedData	-- EncKrbPrivPart
}

EncKrbPrivPart ::= SEQUENCE {
	user-data[0]			OCTET STRING,
	timestamp[1]			UTCTime,
	msec[2]				INTEGER,
	addresses[3]			HostAddresses
}

END
