/*
 * Copyright 1991-1994 by The University of Texas at Austin
 * All rights reserved.
 *
 * For infomation contact:
 * Rick Watson
 * University of Texas
 * Computation Center, COM 1
 * Austin, TX 78712
 * r.watson@utexas.edu
 * 512-471-3241
 */

#include <AppleTalk.h>
#include <Devices.h>
#include <Lists.h>
#include <Menus.h>
#include <Packages.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "MacTCPCommonTypes.h"
#include "AddressXlation.h"
#include "UDPPB.h"
#include "TCPPB.h"
#include "GetMyIPAddr.h"
	
#include "kadm.h"
#include "krb_driver.h"
#include "glue.h"
#include "kconfig.h"

#include "kconfig.proto.h"
#include "kadm.proto.h"
#include "desproto.h"

int private_msg_ver = KRB_PROT_VERSION;
Boolean kerberos_debug = 0;				/* ddd */
int kerberos_debug_packet = 0;
static int ONE = 1;
static short mactcp = 0;

extern queuetype serverQ;
extern krbHiParmBlock khipb;
extern krbParmBlock klopb;

/*
 * kerberos_changepw
 * Return error or zero if ok
 */
int kerberos_changepw (char *name, char *password, char *new, char **reason)
{
	int s;
	int rc = 0;
	int life = 255;						/* 255 * 5 minutes */
	char *realm, *instance, *sinstance;
	char uname[ANAME_SZ], uinstance[INST_SZ], urealm[REALM_SZ];
	char service[256];
	servertype *sp;
	des_cblock newkey;
	unsigned char snewkey[1+8];
	CREDENTIALS *cr;
	unsigned char buf[1300];				/* changepw credentials buffer */
	des_cblock sessionKey;

	*reason = "unknown";
	krb_parse_principal(name, uname, uinstance, urealm);

	/*
	 * If the user specified a realm, try to match it up with 
	 * a realm that we know about. Try case-sensitive first,
	 * then case insensitive so the user doesn't have to worry about
	 * case matching. If no match, bomb out immediately.
	 */
	if (urealm[0]) {
		for (sp = (servertype *)serverQ; sp; sp = sp->next)
			if (sp->admin && (strcmp(urealm, sp->realm) == 0))
				break;
		if (!sp) 
			for (sp = (servertype *)serverQ; sp; sp = sp->next)
				if (sp->admin && (ustrcmp(urealm, sp->realm) == 0))
					break;
		if (!sp) {
			*reason = "Could not find admin server for specified realm.";
			return -1;
		}
		strcpy(urealm, sp->realm);		/* insure correct case */
		realm = urealm;
	} else {							/* get local realm */
		klopb.uRealm = urealm;
		if (s = lowcall(cKrbGetLocalRealm))
			strcpy(urealm, "");
		realm = urealm;
	}

	if (uinstance[0])
		instance = uinstance;
	else
		instance = "";

	sinstance = realm;

	/*
	 * Get password changing credentials.
	 * changepw.kerberos@realm user.instance
	 * We shouldn't keep these around after using them.
	 * 
	 * First, setup the username and old password the user typed in.
	 */
	khipb.user = uname;
	if (s = hicall(cKrbSetUserName)) {
		*reason = "cKrbSetUserName";
		return s;
	}
	khipb.user = password;
	if (s = hicall(cKrbSetPassword)) {
		*reason = "cKrbSetPassword";
		return s;
	}
	
	strcpy(service, "changepw.kerberos@");
	strcat(service, realm);
	bzero(&khipb, sizeof(krbHiParmBlock));
	khipb.service = service;
	khipb.buf = (char *)buf;				/* where to build it */
	khipb.checksum = 0;
	khipb.buflen = sizeof(buf);
	if (s = hicall(cKrbCacheInitialTicket)) {
		*reason = "cKrbCacheInitialTicket";	/* ddd */
		return s;
	}
	bcopy(khipb.sessionKey, sessionKey, sizeof(sessionKey));	/* save the session key */

	/*
	 * Change the new password to a key.
	 */
    (void)des_string_to_key(new, (unsigned char *)newkey);

    /* 
	 * insert code, change key to stream 
	 */
	snewkey[0]  = (unsigned char) CHANGE_PW;
    bcopy((char *) (((long *) newkey) + 1), &snewkey[1], 4);
    bcopy((char *) (((long *) newkey)), &snewkey[5], 4);

    s = kadm_cli_send(snewkey, sizeof(snewkey), uname, uinstance, urealm);
	if (s) {
		*reason = "kadm_cli_send";			/* ddd */
		rc = s;
		goto xit;
	}

	rc = 0;

xit:
#ifdef notdef /* ddd */	
	/* 
	 * destroy changepw credentials
	 */
	if (cr = krb_get_cred("changepw", "kerberos", urealm)) {
		qunlink(&k_credentialsQ, cr);
		freecredentials(cr);
	}
#endif

	return rc;
}


/*
 * kadm_cli_send
 *	recieves   : opcode, packet, packet length, serv_name, serv_inst
 *	returns    : return code from the packet build, the server, or
 *			 something else 
 *
 * It assembles a packet as follows:
 *	 8 bytes    : VERSION STRING
 *	 4 bytes    : LENGTH OF MESSAGE DATA and OPCODE
 *		    : KTEXT
 *		    : OPCODE       \
 *		    : DATA          > Encrypted (with make priv)
 *		    : ......       / 
 *
 * If it builds the packet and it is small enough, then it attempts to open the
 * connection to the admin server.  If the connection is succesfully open
 * then it sends the data and waits for a reply. 
 */

/*
 * unsigned char *st_dat:	theactual data
 * int st_siz:		length of said data
 * unsigned char **ret_dat: 	to give return info
 * int *ret_siz:	length of returned info
 */

int kadm_cli_send (unsigned char *st_dat, int st_siz, char *uname, char *uinstance, char *urealm)
{
	int s;
    unsigned char *priv_pak = 0;		/* private version of the packet */
    int priv_len;						/* length of private packet */
    unsigned long cksum;				/* checksum of the packet */
    MSG_DAT mdat;
	CREDENTIALS cred, *cr = &cred;
	paktype *pak = 0;
	unsigned char *pp;					/* packet build pointer */
	long tmpl;
	tcprequest *tcprequest = 0;
	long error = KRBE_FAIL;				/* preset general failure */
	des_cblock sess_key;
	Key_schedule sess_sched;
	servertype *sp;

    if (!(pak = newpaktype(2048)))
		goto err;
	pp = pak->data;

    strncpy((char *)pp, KADM_VERSTR, KADM_VERSIZE);
	pp += KADM_VERSIZE;

	/*
	 * Find password changing credentials that we previously requested.
	 */
	bzero(cr, sizeof(CREDENTIALS));
	strcpy(cr->service, "changepw");
	strcpy(cr->instance, "kerberos");
	strcpy(cr->realm, urealm);
	bzero(&klopb, sizeof(klopb));
	klopb.uName = uname;
	klopb.uInstance = uinstance;
	klopb.uRealm = urealm;
	klopb.cred = &cred;
	if (s = lowcall(cKrbGetCredentials)) {
		error = s;
		goto err;
	}

	/*
	 * Open a socket so that we will have addresses and ports for
	 * idiotic krb_mk_priv().
	 */
	if (!(tcprequest = (struct tcprequest *)NewPtrClear(sizeof(struct tcprequest)))) {
		error = KRBE_MEM;
		goto err;
	}
	tcprequest->remotePort = 751;						/* admin port */

	/*
	 * Find admin server with the correct realm.
	 * ... may need to make better way to map realms to servers/admin servers.
	 */
	for (sp = (servertype *)serverQ; sp; sp = sp->next)
		if (sp->admin && (strcmp(urealm, sp->realm) == 0))
			break;

	if (sp)
		tcprequest->remoteHost = lookupaddr(sp->host);
	else
		goto err;
		
	if (!tcprequest->remoteHost)
		goto err;
		
	if (!tcp_open(tcprequest))
		goto err;

	bcopy((char *)cr->session, (char *) sess_key, sizeof(des_cblock));
	/* bzero((char *)cr->session, sizeof(des_cblock)); ??? */
	des_key_sched(sess_key, sess_sched);

    /* 
	 * 200 bytes for extra info case 
	 */
    priv_pak = (unsigned char *)NewPtrClear(st_siz + 200);
    if ((priv_len = krb_mk_priv(st_dat, priv_pak, (unsigned long)st_siz,
								sess_sched, sess_key, tcprequest)) < 0)
		goto err;

    /* 
	 * here is the length of priv data.  receiver calcs
	 * size of authenticator by subtracting vno size, priv size, and
	 * sizeof(unsigned long) (for the size indication) from total size 
	 */
	tmpl = htonl(priv_len);
	bcopy(&tmpl, pp, sizeof(long));
	pp += sizeof(long);							/* priv_len: length of priv_pak */

#ifdef notdef
	if (kerberos_debug_packet)
		khexout(priv_pak, priv_len, "KRB:", "priv_pak ");
#endif

    cksum = des_quad_cksum(priv_pak, (unsigned long *)0, (long)priv_len, 0,
					   (unsigned char *)sess_key);

#ifdef notdef
	if (kerberos_debug_packet) {
		khexout(&cksum, 4, "KRB:", "quad checksum ");
		khexout(sess_key, 8, "KRB:", "session key ");
		khexout(priv_pak, priv_len, "KRB:", "priv pak");
	}
#endif

	pp += krb_build_ap(pp, cr, urealm, cksum);	/* KRB_AP_REQ msg */

    bcopy(priv_pak, pp, priv_len);				/* priv_pak */
	pp += priv_len;
    DisposePtr((Ptr)priv_pak);
	priv_pak = 0;

	/*
     * Transmit request packet and get reply packet.
	 */
	pak->len = pp - pak->data;
#ifdef notdef
	if (kerberos_debug_packet)
		khexout(pak->data, pak->len, "KRB:", "kpasswd request packet ");
#endif
	pak = krb_ask_tcp(pak, urealm, tcprequest);
	if (!pak) {
		error = KRBE_TIMO;				/* Timeout */
		goto err;
	}

	/*
	 * Process reply packet.
	 */
#ifdef notdef
	if (kerberos_debug_packet)
		khexout(pak->data, pak->len, "KRB:", "kpasswd response packet ");
#endif

    /* 
	 * first see if it's a YOULOSE 
	 */
    if ((pak->len >= KADM_VERSIZE) &&
		!strncmp(KADM_ULOSE, (char *)pak->data, KADM_VERSIZE)) {

		/* it's a youlose packet */
		if (pak->len < KADM_VERSIZE + sizeof(long)) {
			goto err;
		}

		bcopy(pak->data + KADM_VERSIZE, (char *)&error, sizeof(long));
		error = ntohl(error);
		goto err;
    }

    /* 
	 * need to decode the ret_dat 
	 */
    if (error = krb_rd_priv(pak->data, (unsigned long)pak->len, sess_sched,
							 sess_key, tcprequest, &mdat))
		goto err;

    if (mdat.app_length < KADM_VERSIZE + 4)	{			/* if too short */
		goto err;
	}
    if (strncmp((char *)mdat.app_data, KADM_VERSTR, KADM_VERSIZE)) { /* if bad ver */
		goto err;
	}
    bcopy((char *)mdat.app_data+KADM_VERSIZE, (char *)&error, sizeof(unsigned long));
    error = ntohl((unsigned long)error);

#ifdef notdef	/* don't care about rest of data */
    if (!(return_dat = (unsigned char *)xmalloc((unsigned)(mdat.app_length -
												   KADM_VERSIZE - sizeof(unsigned long)))))
		RET_N_FREE2(KADM_NOMEM);
    bcopy((char *) mdat.app_data + KADM_VERSIZE + sizeof(unsigned long),
		  (char *)return_dat,
		  (int)mdat.app_length - KADM_VERSIZE - sizeof(unsigned long));

    free((char *)*ret_dat);
    clear_secrets();
    *ret_dat = return_dat;
    *ret_siz = mdat.app_length - KADM_VERSIZE - sizeof(unsigned long);
#endif

err:	
	if (priv_pak)
		DisposePtr((Ptr)priv_pak);
	if (pak)
		DisposePtr((Ptr)pak);
	if (tcprequest)
		tcp_freerequest(tcprequest);

    return error;
}


/*
 * krb_ask_tcp
 * Sends a request to a Kerberos server and waits for a response.
 * Timeouts SHOULD... cause other servers in the list to be tried.
 * 
 * The respose packet, if any, is returned.
 * The request packet is discarded.
 *
 * PROBABLY SHOULD USE REALM TO SPECIFY WHICH SERVERS ARE USABLE. ???
 */
paktype *krb_ask_tcp (paktype *pak, char *realm, tcprequest *tcprequest)
{
	paktype *newpak;
	servertype *sp;
		
	/*
	 * Find a server with the correct realm.
	 */
	for (sp = (servertype *)serverQ; sp; sp = sp->next)
		if (strcmp(realm, sp->realm) == 0)
			break;
	if (!sp) {
		disposepak(pak);
#ifdef notdef
		if (kerberos_debug || kerberos_debug_packet)
			buginf("\nKRB: krb_ask_tcp: no server for realm \"%s\"", realm);
#endif
		return 0;
	}
	
	/*
	 * Build and transmit the request
	 */
	tcprequest->pak = pak;		
	tcprequest->timeout = 2;				/* timeout period in seconds */
	tcprequest->retries = 8;				/* number of retransmits allowed */
	tcprequest->remoteHost = lookupaddr(sp->host);
	if (!tcp_transmit(tcprequest))
		return ((paktype *)0);

	/*
	 * Wait for request complete
	 */
	for (;;) {
		/* ... wait next event or spincursor ... */
		
		switch (tcprequest->result) {
		case UR_READERROR:
			disposepak(pak);
			return 0;

		case UR_TIMEOUT:
			disposepak(pak);
			return 0;

		case UR_READDONE:
			disposepak(pak);
			newpak = newpaktype(tcprequest->rpb.csParam.receive.rcvBuffLen);
			if (newpak) {
				bcopy(tcprequest->rpb.csParam.receive.rcvBuff, newpak->data,
				      tcprequest->rpb.csParam.receive.rcvBuffLen);
				newpak->len = tcprequest->rpb.csParam.receive.rcvBuffLen;
			}
			return newpak;
		} /* switch tcprequest->result */
	}
}


/*
 * krb_parse_principal
 * Parse a name which may include an instance and realm. 
 * The return locations are assumed to be of sufficient
 * size, bounded by the _SZ constants.
 * 
 * If periods are allowed in kerberos names, this code will need
 * to be smarter. The case of rick.watson@realm is ambiguous and
 * joe.smith.rcmd@realm is parsed incorrectly.
 */
void krb_parse_principal (char *user, char *uname, char *uinst, char *urealm)
{
	char *cp;
	char tmp[ANAME_SZ + INST_SZ + REALM_SZ];

	strncpy(tmp, user, ANAME_SZ + INST_SZ + REALM_SZ);

	if (cp = strchr(tmp, '@')) {
		*cp++ = '\0';
		strncpy(urealm, cp, REALM_SZ);
	} else
		*urealm = '\0';

	if (cp = strchr(tmp, '.')) {
		*cp++ = '\0';
		strncpy(uinst, cp, INST_SZ);
	} else
		*uinst = '\0';

	strncpy(uname, tmp, ANAME_SZ);
}


/*
 * krb_build_ap
 *
 * Build a KRB_AP_REQ message.
 * Returns the message length.
 *
 * cp:    where to build the message
 */

int krb_build_ap (char *cp, CREDENTIALS *cr, char *srealm, long checksum)
{
	int len;
	long gmtunixtime;
	unsigned char *sp, *ap, *lenAp;
	KTEXT_ST *ticket;
	Key_schedule key_s;
	struct timeval tv;
	struct timezone tz;

	ticket = &cr->ticket_st;

	sp = cp;
	/*
	 * pvno, type, kvno, srealm, ticket length, authenticator length.
	 */
	*cp++ = KRB_PROT_VERSION;					/* pvno */
	*cp++ = AUTH_MSG_APPL_REQUEST | HOST_BYTE_ORDER; /* type | B */
	*cp++ = (unsigned char) cr->kvno;			/* kvno */
	cp = stringcopy(cp, srealm);				/* srealm */
	*cp++ = (unsigned char) ticket->length;		/* len_T */
	lenAp = cp++;								/* save pointer to len_A */
	/*
	 * ticket
	 */
	bcopy((char *)(ticket->dat), cp, ticket->length); /* ticket */
	cp += ticket->length;
	/*
	 * Build authenticator and encrypt it using the session key.
	 */
	ap = cp;
	cp = stringcopy(cp, cr->pname);				/* Principal's cname */
	cp = stringcopy(cp, cr->pinst);				/* Principal's instance */
	cp = stringcopy(cp, cr->realm);				/* Authentication domain */
	bcopy((char *)&checksum, (char *)cp, 4);	/* Checksum */
	cp += 4;
#ifdef notdef /* ... */
	*cp++ = (char)(msclock & 0xff);				/* times */
#else
	*cp++ = 1;
#endif
	gettimeofdaynet(&tv, &tz);
	gmtunixtime = tv.tv_sec;
	bcopy(&gmtunixtime, cp,	 4);
	cp += 4;
	len = cp - ap;
	len = ((len+7)/8)*8;		/* Fill to a multiple of 8 bytes for DES */
	*lenAp = len;
	cp = ap + len;
#ifdef notdef
	if (kerberos_debug_packet)					/* temp !!! ??? */
		khexout((char *)sp, cp - sp, "KRB:", 
				"krb_build_ap (unencrypted) message:");
#endif
	des_key_sched((des_cblock)cr->session, key_s);

	/*
	 * The cblock must be word aligned or we'll crash on a 68000, so copy it.
	 */
	des_pcbc_encrypt((unsigned char *)ap, (unsigned char *)ap, (long) len, key_s, 
				 (unsigned char *)cr->session, 1);
	bzero((char *) key_s, sizeof(key_s));		/* clean up */
	len = cp - sp;								/* data length */
	return len;
}


/*
 * tcp_open
 */
#define TCP_RBUFSIZE	4096					/* size of receive buffer */
Boolean tcp_open (tcprequest *tcprequest)
{
	int s;
	TCPiopb pb;
	struct GetAddrParamBlock my;
		
	if (!mactcp) {
		if (s = OpenDriver("\p.ipp", &mactcp)) {
			doalert("Could not open .ipp driver: %d", s);
			getout(0);
		}
	}

	if (tcprequest->stream)						/* if stream already open */
		return true;

	if (!(tcprequest->tcpbuf = (char *)NewPtrClear(TCP_RBUFSIZE)))
		return false;

	/*
	 * Create a TCP stream
	 */
	pb.csParam.create.rcvBuff = tcprequest->tcpbuf;
	pb.csParam.create.rcvBuffLen = TCP_RBUFSIZE;
	pb.csParam.create.notifyProc = 0;				/* no ASR */
	pb.csParam.create.userDataPtr = (Ptr)tcprequest;
	pb.ioCompletion = 0;
	pb.ioCRefNum = mactcp;
	pb.csCode = TCPCreate;
	s = PBControl((ParmBlkPtr)&pb, false);
	if (s)
		return false;
	tcprequest->stream = pb.tcpStream;
		

	/*
	 * Open the connection
	 */
	pb.ioCRefNum = mactcp;
	pb.csCode = TCPActiveOpen;
	pb.csParam.open.validityFlags = timeoutValue | timeoutAction;
	pb.csParam.open.ulpTimeoutValue = 60 	/* seconds */;
	pb.csParam.open.ulpTimeoutAction = 1 	/* 1:abort 0:report */;
	pb.csParam.open.commandTimeoutValue = 0;
	pb.csParam.open.remoteHost = tcprequest->remoteHost;
	pb.csParam.open.remotePort = tcprequest->remotePort;
	pb.csParam.open.localHost = 0;
	pb.csParam.open.localPort = 0;
	pb.csParam.open.dontFrag = 0;
	pb.csParam.open.timeToLive = 0;
	pb.csParam.open.security = 0;
	pb.csParam.open.optionCnt = 0;
	s = PBControl((ParmBlkPtr)&pb, false);	
	if (s) {
		tcp_close(tcprequest);
		return false;
	}
	tcprequest->localPort = pb.csParam.open.localPort;

	/*
	 * Fill in our local ip address
	 */
	bzero(&my, sizeof(my));
	my.ioCRefNum = mactcp;
	my.csCode = ipctlGetAddr;
	s = PBControl((ParmBlkPtr)&my, false);
	if (s)
		return false;
	tcprequest->localHost = my.ourAddress;

	return true;
}
	

/*
 * tcp_close
 * Close the stream associated with a request entry
 */
void tcp_close (tcprequest *tcprequest)
{
	int s;
	TCPiopb pb;
	
	if (!tcprequest->stream)
		return;
		
#ifdef notdef
	pb.csParam.close.validityFlags = timeoutValue | timeoutAction;
	pb.csParam.close.ulpTimeoutValue = 60 /* seconds */;
	pb.csParam.close.ulpTimeoutAction = 1 /* 1:abort 0:report */;
#endif
	pb.ioCompletion = 0;
	pb.ioCRefNum = mactcp;
	pb.tcpStream = tcprequest->stream;
	pb.csCode = TCPRelease;

	s = PBControl((ParmBlkPtr)&pb, false);
	/* ignore error */

	tcprequest->stream = 0;

	if (tcprequest->tcpbuf)
		DisposePtr((Ptr)tcprequest->tcpbuf);
	tcprequest->tcpbuf = 0;
}


/*
 * tcp_transmit
 */
Boolean tcp_transmit (tcprequest *tcprequest)
{
	int s;
	TCPiopb *pb;

	/*
	 * Get a socket so that we will be able to identify responses.
	 */
	if (!tcp_open(tcprequest))
		return false;
		
	pb = &tcprequest->wpb;
	if (pb->ioResult == 1) {				/* if busy */
		DebugStr("\ptcp_transmit: pb is busy");
		return false;
	}
	bzero(pb, sizeof(struct TCPiopb));
	pb->csCode = TCPSend;
	pb->ioCompletion = 0;
	pb->ioCRefNum = mactcp;
	pb->tcpStream = tcprequest->stream;

	pb->csParam.send.validityFlags = timeoutValue | timeoutAction;
	pb->csParam.send.ulpTimeoutValue = 30 	/* seconds */;
	pb->csParam.send.ulpTimeoutAction = 1 	/* 1:abort 0:report */;
	pb->csParam.send.pushFlag = true;
	pb->csParam.send.urgentFlag = false;

	pb->csParam.send.wdsPtr = (Ptr)&tcprequest->wds[0];
	pb->csParam.send.userDataPtr = (Ptr)tcprequest;

	tcprequest->wds[0].length = sizeof(tcprequest->xlen); /* transmit length */
	tcprequest->wds[0].ptr = (Ptr)&tcprequest->xlen;
	tcprequest->xlen = tcprequest->pak->len;
	tcprequest->wds[1].length = tcprequest->pak->len;
	tcprequest->wds[1].ptr = tcprequest->pak->data;
	tcprequest->wds[2].length = 0;
	tcprequest->wds[2].ptr = 0;

	s = PBControl((ParmBlkPtr)pb, true);
	if (s)
		return false;
		
	tcprequest->readheader = true;
	if (!tcp_startread(tcprequest))				/* setup read/timeout */
		return false;

	return true;
}

/*
 * tcp_startread
 * Start a read with a timeout. A timeout will trigger a 
 * request failure.
 */
Boolean tcp_startread (tcprequest *tcprequest)
{
	int s;
	TCPiopb *pb;
	
	pb = &tcprequest->rpb;
	if (pb->ioResult == 1)						/* if read busy */
		return false;
		
	bzero(pb, sizeof(struct TCPiopb));

	pb->csCode = TCPRcv;
	pb->csParam.receive.commandTimeoutValue = 30;

	/*
	 * First, read a  length header.
	 */
	if (tcprequest->readheader) {
		pb->csParam.receive.rcvBuffLen = sizeof(tcprequest->header);
		pb->csParam.receive.rcvBuff = (Ptr)&tcprequest->header;
	} else {
		pb->csParam.receive.rcvBuffLen = tcprequest->header;
		pb->csParam.receive.rcvBuff = tcprequest->rbuf;
	}

	pb->ioCRefNum = mactcp;
	pb->tcpStream = tcprequest->stream;
	pb->ioCompletion = (TCPIOCompletionProc)tcp_readdone;
	pb->csParam.receive.userDataPtr = (Ptr)tcprequest;

	s = PBControl((ParmBlkPtr)pb, true);
	if (s)
		return false;
	return true;
}


/*
 * tcp_readdone
 * IO Completion routine called when a read request completes or times out
 */
void tcp_readdone ()
{
	TCPiopb *pb;
	tcprequest *tcprequest;
	
	pb = (TCPiopb *)getA0();					/* recover pb */
	tcprequest = (struct tcprequest *)pb->csParam.receive.userDataPtr;

	if (pb->ioResult == commandTimeout) {		/* if command timeout */
		tcprequest->result = UR_TIMEOUT;
		return;
	} 
	
	if (pb->ioResult != noErr) { 				/* error */
		tcprequest->result = UR_READERROR;
		return;
	}
	
	if (tcprequest->readheader) {		/* if we just read header */
		tcprequest->readheader = false;	/* read the packet now */
		tcp_startread(tcprequest);
		return;
	}

	/*
	 * Read has completed successfully. Data pointers are in the rpb.
	 * Signal success to user-level code.
	 */
	tcprequest->result = UR_READDONE;			/* read has completed */
}


/*
 * tcp_freerequest
 */
void tcp_freerequest (tcprequest *request)
{
	if (request->stream)
		tcp_close(request);

	DisposePtr((Ptr)request);
}


paktype *newpaktype (int len)
{
	paktype *pak;
	
	if (pak = (paktype *)NewPtrClear(sizeof(paktype) + len)) {
		pak->len = len;
		pak->data = (unsigned char *)pak + sizeof(paktype);
	}
	return pak;
}


void disposepak (paktype *pak)
{
	DisposePtr((Ptr)pak);
}


/*
 * stringcopy
 * This version of strcpy writes a null string into dst
 * if the src string is a null pointer.	 It returns 
 * a pointer to the byte after the string terminator.
 */
void *stringcopy (void *dst, void *src)
{
	char *d = dst;
	char *s = src;

	if (s)
		while (*s)
			*d++ = *s++;
	*d++ = '\0';

	return (void *)d;
}


/*
 * ustrcmp
 * Compare strings, ignoring case.
 * Return 0 if strings are equal
 */
int ustrcmp (char *src, char *dst)
{
	Boolean s;
	
	c2pstr(src);
	c2pstr(dst);
	s = EqualString(src, dst, false, false);
	p2cstr(src);
	p2cstr(dst);
	return (s)? 0 : 1;
}


/*
 * krb_mk_priv() constructs an AUTH_MSG_PRIVATE message.  It takes
 * some user data "in" of "length" bytes and creates a packet in "out"
 * consisting of the user data, a timestamp, and the sender's network
 * address.
 * The packet is encrypted by pcbc_encrypt(), using the given
 * "key" and "schedule".
 * The length of the resulting packet "out" is
 * returned.
 *
 * It is similar to krb_mk_safe() except for the additional key
 * schedule argument "schedule" and the fact that the data is encrypted
 * rather than appended with a checksum.  Also, the protocol version
 * number is "private_msg_ver", defined in krb_rd_priv.c, rather than
 * KRB_PROT_VERSION, defined in "krb.h".
 *
 * The "out" packet consists of:
 *
 * Size			Variable		Field
 * ----			--------		-----
 *
 * 1 byte		private_msg_ver		protocol version number
 * 1 byte		AUTH_MSG_PRIVATE |	message type plus local
 *			    HOST_BYTE_ORDER		byte order in low bit
 *
 * 4 bytes		c_length		length of encrypted data
 *
 * ===================== begin encrypt ================================
 * 
 * 4 bytes		length				length of user data
 * length		in					user data
 * 1 byte		msg_time_5ms		timestamp milliseconds
 * 4 bytes		sender->sin.addr.s_addr	sender's IP address
 *
 * 4 bytes		msg_time_sec or		timestamp seconds with
 *				-msg_time_sec		direction in sign bit
 *
 * 0<=n<=7  bytes	pad to 8 byte multiple	zeroes
 *			(done by pcbc_encrypt())
 *
 * ======================= end encrypt ================================
 */

/*
 * unsigned char *in                   application data
 * unsigned char *out                  put msg here, leave room for
 *                                header! breaks if in and out
 *                                (header stuff) overlap
 * unsigned long length                length of in data
 * Key_schedule schedule        precomputed key schedule
 * C_Block key                  encryption key for seed and ivec
 * struct tcprequest *			tcp request struct for send/rcvr addresses
 */

long krb_mk_priv (unsigned char *in, unsigned char *out, unsigned long length, 
				  des_key_schedule schedule, C_Block key, 
				  struct tcprequest *tcprequest)
{
    register unsigned char *p, *q;
    static unsigned  char *c_length_ptr;
	long msg_time_sec;
	unsigned char msg_time_5ms;
	unsigned long c_length;
	struct timeval tv;
	struct timezone tz;

    /*
     * get the current time to use instead of a sequence #, since
     * process lifetime may be shorter than the lifetime of a session
     * key.
     */
	
	gettimeofdaynet(&tv, &tz);
    msg_time_sec = (long)tv.tv_sec;
    msg_time_5ms = 1;

    p = out;

    *p++ = private_msg_ver;
    *p++ = AUTH_MSG_PRIVATE | HOST_BYTE_ORDER;

    /* calculate cipher length */
    c_length_ptr = p;
    p += sizeof(c_length);

    /* start for encrypted stuff */
    q = p;

    /* stuff input length */
    bcopy((char *)&length, (char *)p, sizeof(length));
    p += sizeof(length);

    /* make all the stuff contiguous for checksum and encryption */
    bcopy((char *)in, (char *)p, (int)length);
    p += length;

    /* stuff time 5ms */
    bcopy((char *)&msg_time_5ms, (char *)p, sizeof(msg_time_5ms));
    p += sizeof(msg_time_5ms);

    /* stuff source address */
    bcopy((char *)&tcprequest->localHost, (char *)p, sizeof(tcprequest->localHost));
    p += sizeof(tcprequest->localHost);

    /*
     * direction bit is the sign bit of the timestamp.  Ok
     * until 2038??
     */
    /* 
	 * For compatibility with broken old code, compares are done in VAX 
     * byte order (LSBFIRST) 
	 */ 
    if (lsb_net_ulong_less(tcprequest->localHost,	 /* src < recv */ 
			   tcprequest->remoteHost) == -1) 
        msg_time_sec =  -msg_time_sec; 
    else if (lsb_net_ulong_less(tcprequest->localHost, 
								tcprequest->remoteHost) == 0) 
        if (lsb_net_ushort_less(tcprequest->localPort, tcprequest->remotePort) == -1) 
            msg_time_sec = -msg_time_sec; 
    /* stuff time sec */
    bcopy((char *)&msg_time_sec, (char *)p, sizeof(msg_time_sec));
    p += sizeof(msg_time_sec);

    /*
     * All that for one tiny bit!  Heaven help those that talk to
     * themselves.
     */

#ifdef NOTDEF
    /*
     * calculate the checksum of the length, address, sequence, and
     * inp data
     */
    cksum =  quad_cksum(q,NULL,p-q,0,key);
    if (krb_debug)
        printf("\ncksum = %u",cksum);
    /* stuff checksum */
    bcopy((char *) &cksum,(char *) p,sizeof(cksum));
    p += sizeof(cksum);
#endif

    /*
     * All the data have been assembled, compute length and encrypt
     * starting with the length, data, and timestamps use the key as
     * an ivec.
     */

    c_length = p - q;
    c_length = ((c_length + sizeof(C_Block) -1)/sizeof(C_Block)) *
        sizeof(C_Block);

    /* stuff the length */
    bcopy((char *) &c_length, (char *)c_length_ptr, sizeof(c_length));

#ifdef notdef
	if (kerberos_debug_packet)
		khexout(q, p-q, "KRB:", "krb_mk_priv unencrypted ");
#endif

    /* pcbc encrypt, pad as needed, use key as ivec */
    des_pcbc_encrypt((des_cblock) q, (des_cblock) q, (long) (p-q), schedule,
                 (des_cblock)key, 1); /* ENCRYPT */

    return (q - out + c_length);        /* resulting size */
}


/*
 * krb_rd_priv() decrypts and checks the integrity of an
 * AUTH_MSG_PRIVATE message.  Given the message received, "in",
 * the length of that message, "in_length", the key "schedule"
 * and "key" to decrypt with, and the network addresses of the
 * "sender" and "receiver" of the message, krb_rd_safe() returns
 * RD_AP_OK if the message is okay, otherwise some error code.
 *
 * The message data retrieved from "in" are returned in the structure
 * "m_data".  The pointer to the decrypted application data
 * (m_data->app_data) refers back to the appropriate place in "in".
 *
 * See the file "mk_priv.c" for the format of the AUTH_MSG_PRIVATE
 * message.  The structure containing the extracted message
 * information, MSG_DAT, is defined in "krb.h".
 */

/*
 * unsigned char *in				pointer to the msg received
 * unsigned long in_length;		length of "in" msg
 * Key_schedule schedule;	precomputed key schedule
 * C_Block key				encryption key for seed and ivec
 * struct tcprequest *tcprequest;
 * MSG_DAT *m_data			various input/output data from msg
 */

/*
 * NOTE: the original routine had sender and receiver where we only
 * have tcprequest. So, we have to reverse the sense of the sender
 * and receiver.
 */
#define sender remoteHost
#define receiver localHost
#define senderp remotePort
#define receiverp localPort

long krb_rd_priv (unsigned char *in, unsigned long in_length, Key_schedule schedule,
				 C_Block key, struct tcprequest *tcprequest, 
				 MSG_DAT *m_data)
{
    register unsigned char *p, *q;
    static unsigned long src_addr;	/* Can't send structs since no guarantees on size */
	int swap_bytes = 0;
	unsigned long c_length;
	long delta_t;
	struct timeval tv;
	struct timezone tz;
	
    p = in;			/* beginning of message */
    swap_bytes = 0;

    if (*p++ != KRB_PROT_VERSION && *(p-1) != 3)
        return KRBE_FAIL;

    /* ...??? private_msg_ver = *(p-1); */
    if (((*p) & ~1) != AUTH_MSG_PRIVATE)
        return KRBE_FAIL;

    if ((*p++ & 1) != HOST_BYTE_ORDER)
        swap_bytes++;

    /* get cipher length */
    bcopy((char *)p, (char *)&c_length, sizeof(c_length));
    if (swap_bytes)
        c_length = swapl(c_length);
    p += sizeof(c_length);
    /* check for rational length so we don't go comatose */
    if (VERSION_SZ + MSG_TYPE_SZ + c_length > in_length)
        return KRBE_FAIL;

    /*
     * decrypt to obtain length, timestamps, app_data, and checksum
     * use the session key as an ivec
     */

    q = p;			/* mark start of encrypted stuff */

    /* pcbc decrypt, use key as ivec */
    des_pcbc_encrypt((des_cblock)q, (des_cblock)q, (long) c_length,
                 schedule, (des_cblock)key, 0);	/* DECRYPT */

    /* safely get application data length */
    bcopy((char *)p, (char *)&(m_data->app_length), sizeof(m_data->app_length));
    if (swap_bytes)
        m_data->app_length = swapl(m_data->app_length);
    p += sizeof(m_data->app_length);    /* skip over */

    if (m_data->app_length + sizeof(c_length) + sizeof(in_length) +
        sizeof(m_data->time_sec) + sizeof(m_data->time_5ms) +
        sizeof(src_addr) + VERSION_SZ + MSG_TYPE_SZ
        > in_length)
        return KRBE_FAIL;

    /* we're now at the decrypted application data */
    m_data->app_data = p;

    p += m_data->app_length;

    /* safely get time_5ms */
    bcopy((char *) p, (char *)&(m_data->time_5ms),
	  sizeof(m_data->time_5ms));
    /*  don't need to swap-- one byte for now */
    p += sizeof(m_data->time_5ms);

    /* safely get src address */
    bcopy((char *) p,(char *)&src_addr,sizeof(src_addr));
    /* don't swap, net order always */
    p += sizeof(src_addr);

    if (src_addr != (unsigned long) tcprequest->sender)
		return KRBE_FAIL;

    /* safely get time_sec */
    bcopy((char *) p, (char *)&(m_data->time_sec), sizeof(m_data->time_sec));
    if (swap_bytes) 
		m_data->time_sec = swapl(m_data->time_sec);

    p += sizeof(m_data->time_sec);

    /* 
	 * check direction bit is the sign bit.
     * For compatibility with broken old code, compares are done in VAX 
	 * byte order (LSBFIRST) 
	 */ 
    if (lsb_net_ulong_less(tcprequest->sender, tcprequest->receiver) == -1) 
		/* src < recv */ 
		m_data->time_sec =  - m_data->time_sec; 
    else if (lsb_net_ulong_less(tcprequest->sender, 
								tcprequest->receiver) == 0) 
		if (lsb_net_ushort_less(tcprequest->senderp, tcprequest->receiverp) == -1)
			/* src < recv */
			m_data->time_sec =  - m_data->time_sec; 
    /*
     * all that for one tiny bit!
     * Heaven help those that talk to themselves.
     */

    /* check the time integrity of the msg */

	gettimeofdaynet(&tv, &tz);
    delta_t = abs((int)((long) tv.tv_sec - m_data->time_sec));
    if (delta_t > CLOCK_SKEW)
		return KRBE_SKEW;

    /*
     * caller must check timestamps for proper order and
     * replays, since server might have multiple clients
     * each with its own timestamps and we don't assume
     * tightly synchronized clocks.
     */

#ifdef notdef
    bcopy((char *) p,(char *)&cksum,sizeof(cksum));
    if (swap_bytes) 
		cksum = swapl(cksum)
    /*
     * calculate the checksum of the length, sequence,
     * and input data, on the sending byte order!!
     */
    calc_cksum = quad_cksum(q,NULL,p-q,0,key);

    if (krb_debug)
	printf("\ncalc_cksum = %u, received cksum = %u",
	       calc_cksum, cksum);
    if (cksum != calc_cksum)
	return RD_AP_MODIFIED;
#endif

    return 0;        /* OK == 0 */
}


/*
 * lookupaddr
 * Lookup address
 * Return 0 if not found
 */
unsigned long lookupaddr (char *hostname)
{
	int s;
	struct hostInfo *rtnStruct = 0;
	char done = 0;
	unsigned long addr;

	if (!(rtnStruct = (struct hostInfo *) NewPtrClear(sizeof(struct hostInfo)))) {
		goto xit;
	}

	s = StrToAddr(hostname, rtnStruct, dnsDone, (char *)&done);
	if (s && (s != cacheFault)) {
		goto xit;
	}	

	/*
	 * wait for the result
	 * ... should timeout? (dnr probably does)
	 * ... should run minimal event loop
	 * ... should finish processing in netevent loop
	 */
	if (s) {
		while (!done)
			;
	}
	
	if (rtnStruct->rtnCode == noErr) {				/* if success */
		addr = rtnStruct->addr[0];
	} else {
		addr = 0;
	}
	
xit:
	if (rtnStruct)
		DisposPtr((Ptr)rtnStruct);
	
	return addr;
}


/*
 * dnsDone
 * completion routine for dns
 */
pascal void dnsDone (struct hostInfo *info, char *userdata)
{
	#pragma unused(info)
	*userdata = 1;
}


/*
 * Junk so Emacs will set local variables to be compatible with Mac/MPW.
 * Should be at end of file.
 * 
 * Local Variables:
 * tab-width: 4
 * End:
 */
