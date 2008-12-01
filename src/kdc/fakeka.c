/*
 * COPYRIGHT NOTICE
 * Copyright (c) 1994 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software_Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 *
 * Converted to Kerberos 5 by Ken Hornstein <kenh@cmf.nrl.navy.mil>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#include <krb5.h>
#include <kadm5/admin.h>
#include <com_err.h>
#include <kerberosIV/krb.h>
#include <kerberosIV/des.h>
#include <k5-platform.h>

#ifndef LINT
static char rcsid[]=
	"$Id$";
#endif

/*
 * Misc macros
 */

#define PAD_TO(x, a) (((u_long)(x) + (a) - 1) & ~((a) - 1))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define MAXFORWARDERS 10
#define HEADER_LEN 8

/*
 * Error values from kautils.h
 * 
 * The security errors are:
 * 	KABADTICKET, KABADSERVER, KABADUSER, and KACLOCKSKEW
 */

#define KADATABASEINCONSISTENT                   (180480L)
#define KANOENT                                  (180484L)
#define KABADREQUEST                             (180490L)     
#define KABADTICKET                              (180504L)
#define KABADSERVER                              (180507L)
#define KABADUSER                                (180508L)
#define KACLOCKSKEW                              (180514L)
#define KAINTERNALERROR                          (180518L)


/*
 * Type definitions
 */

typedef struct packet {
    char *base;
    int len;
    char data[1024];
} *packet_t;

typedef struct rx_header {
    u_int rx_epoch;
    u_int rx_cid;
    u_int rx_callnum;
    u_int rx_seq;
    u_int rx_serial;
    u_char rx_type;
    u_char rx_flags;
    u_char rx_userstatus;
    u_char rx_securityindex;
    u_short rx_spare;
    u_short rx_service;
    u_int rx_request;
} *rx_t;


/*
 * Global vars
 */

char *progname = "fakeka";		/* needed by libkdb.a */
char *localrealm = NULL;
char *localcell = NULL;
krb5_timestamp req_time;
kadm5_config_params realm_params;
int debug = 0;


/*
 * This is a table for the "infamous" CMU ticket lifetime conversion.  If
 * the lifetime is greater than 128, use this table
 */
#define MAX_TICKET_LIFETIME 2592000
static long cmu_seconds[] =
{
  38400,  41055,  43894,  46929,  50174,  53643,  57352,  61318,
  65558,  70091,  74937,  80119,  85658,  91581,  97914,  104684,
  111922,  119661,  127935,  136781,  146239,  156350,  167161,  178720,
  191077,  204289,  218415,  233517,  249663,  266926,  285383,  305116,
  326213,  348769,  372885,  398668,  426233,  455705,  487215,  520903,
  556921,  595430,  636600,  680618,  727679,  777995,  831789,  889303,
  950794,  1016536,  1086825,  1161973,  1242317,  1328217,  1420057,  1518246,
  1623225,  1735463,  1855462,  1983757,  2120924,  2267575,  2424366, 2591999,
  0
};

#if	__STDC__
/*
 * Prototypes for all the functions we define
 */

void perrorexit(char *);
void pexit(char *);
char *kaerror(int);
int get_princ_key(krb5_context, void *, kadm5_principal_ent_t, des_cblock,
		  des_key_schedule);
int check_princ(krb5_context, void *, char *, char *, kadm5_principal_ent_t);

int make_reply_packet(krb5_context, void *, packet_t, int, int, int,
		      char *, char *, char *, char *,
		      des_cblock, des_key_schedule, char *);

int Authenticate(krb5_context, void *, char *, packet_t, packet_t);
int GetTicket(krb5_context, void *, char *, packet_t, packet_t);
void process(krb5_context, void *, char *, packet_t, packet_t);
#endif


/*
 * Helpers for exiting with errors
 */

void perrorexit(str)
char *str;
{
    perror(str);
    exit(1);
}

void pexit(str)
char *str;
{
    printf("%s\n", str);
    exit(1);
}


/*
 * Translate error codes into strings.
 */

char *kaerror(e)
int e;
{
    static char buf[1024];

    switch (e) {
    case KADATABASEINCONSISTENT:
	return "database is inconsistent";
    case KANOENT:
	return "principal does not exist";
    case KABADREQUEST:
	return "request was malformed (bad password)";
    case KABADTICKET:
	return "ticket was malformed, invalid, or expired";
    case KABADSERVER:
	return "cannot issue tickets for this service";
    case KABADUSER:
	return "principal expired";
    case KACLOCKSKEW:
	return "client time is too far skewed";
    case KAINTERNALERROR:
	return "internal error in fakeka, help!";
    default:
	snprintf(buf, sizeof(buf), "impossible error code %d, help!", e);
	return buf;
    }
    /*NOTREACHED*/
}

/*
 * Syslog facilities
 */
typedef struct {
	int num;
	char *string;
} facility_mapping;

static facility_mapping mappings[] = {
#ifdef LOG_KERN   
	{ LOG_KERN, "KERN" },
#endif
#ifdef LOG_USER
	{ LOG_USER, "USER" },
#endif
#ifdef LOG_MAIL
	{ LOG_MAIL, "MAIL" },
#endif
#ifdef LOG_DAEMON
	{ LOG_DAEMON, "DAEMON" },
#endif
#ifdef LOG_AUTH
	{ LOG_AUTH, "AUTH" },
#endif
#ifdef LOG_LPR
	{ LOG_LPR, "LPR" },
#endif
#ifdef LOG_NEWS
	{ LOG_NEWS, "NEWS" },
#endif
#ifdef LOG_UUCP
	{ LOG_UUCP, "UUCP" },
#endif
#ifdef LOG_CRON
	{ LOG_CRON, "CRON" },
#endif
#ifdef LOG_LOCAL0
	{ LOG_LOCAL0, "LOCAL0" },
#endif
#ifdef LOG_LOCAL1
	{ LOG_LOCAL1, "LOCAL1" },
#endif
#ifdef LOG_LOCAL2
	{ LOG_LOCAL2, "LOCAL2" },
#endif
#ifdef LOG_LOCAL3
	{ LOG_LOCAL3, "LOCAL3" },
#endif
#ifdef LOG_LOCAL4
	{ LOG_LOCAL4, "LOCAL4" },
#endif
#ifdef LOG_LOCAL5
	{ LOG_LOCAL5, "LOCAL5" },
#endif
#ifdef LOG_LOCAL6
	{ LOG_LOCAL6, "LOCAL6" },
#endif
#ifdef LOG_LOCAL7
	{ LOG_LOCAL7, "LOCAL7" },
#endif
	{ 0, NULL }
};


/*
 * Get the principal's key and key schedule from the db record.
 *
 * Life is more complicated in the V5 world.  Since we can have different
 * encryption types, we have to make sure that we get back a DES key.
 * Also, we have to try to get back a AFS3 or V4 salted key, since AFS
 * doesn't know about a V5 style salt.
 */

int get_princ_key(context, handle, p, k, s)
krb5_context context;
void *handle;
kadm5_principal_ent_t p;
des_cblock k;
des_key_schedule s;
{	
    int rv;
    krb5_keyblock kb;
    kadm5_ret_t retval;

    /*
     * We need to call kadm5_decrypt_key to decrypt the key data
     * from the principal record.  We _must_ have a encryption type
     * of DES_CBC_CRC, and we prefer having a salt type of AFS 3 (but
     * a V4 salt will work as well).  If that fails, then return any
     * type of key we can find.
     *
     * Note that since this uses kadm5_decrypt_key, it means it has to
     * be compiled with the kadm5srv library.
     */

    if ((retval = kadm5_decrypt_key(handle, p, ENCTYPE_DES_CBC_CRC,
				    KRB5_KDB_SALTTYPE_AFS3, 0, &kb,
				    NULL, NULL)))
	if ((retval = kadm5_decrypt_key(handle, p, ENCTYPE_DES_CBC_CRC,
					KRB5_KDB_SALTTYPE_V4, 0, &kb,
					NULL, NULL)))
		if ((retval = kadm5_decrypt_key(handle, p, ENCTYPE_DES_CBC_CRC,
						-1, 0, &kb, NULL, NULL))) {
			syslog(LOG_ERR, "Couldn't find any matching key: %s",
			       error_message(retval));
			return KAINTERNALERROR;
		}

    /*
     * Copy the data from our krb5_keyblock to the des_cblock.  Make sure
     * the size of our key matches the V4/AFS des_cblock.
     */

    if (kb.length != sizeof(des_cblock)) {
	krb5_free_keyblock_contents(context, &kb);
	syslog(LOG_ERR, "Principal key size of %d didn't match C_Block size"
	       " %d", kb.length, sizeof(des_cblock));
	return KAINTERNALERROR;
    }

    memcpy((char *) k, (char *) kb.contents, sizeof(des_cblock));

    krb5_free_keyblock_contents(context, &kb);

    /*
     * Calculate the des key schedule
     */

    rv = des_key_sched(k, s);
    if (rv) {
	memset((void *) k, 0, sizeof(k));
	memset((void *)s, 0, sizeof(s));
	return KAINTERNALERROR;
    }
    return 0;
}


/*
 * Fetch principal from db and validate it.
 *
 * Note that this always fetches the key data from the principal (but it
 * doesn't decrypt it).
 */

int check_princ(context, handle, name, inst, p)
krb5_context context;
void *handle;
char *name, *inst;
kadm5_principal_ent_t p;
{
    krb5_principal princ;
    krb5_error_code code;
    kadm5_ret_t retcode;

    /*
     * Screen out null principals. They are causing crashes here
     * under HPUX-10.20. - vwelch@ncsa.uiuc.edu 1/6/98
     */
    if (!name || (name[0] == '\0')) {
	syslog(LOG_ERR, "screening out null principal");
	return KANOENT;
    }

    /*
     * Build a principal from the name and instance (the realm is always
     * the same).
     */

    if ((code = krb5_build_principal_ext(context, &princ, strlen(localrealm),
					 localrealm, strlen(name), name,
					 strlen(inst), inst, 0))) {
	syslog(LOG_ERR, "could not build principal: %s", error_message(code));
	return KAINTERNALERROR;
    }

    /*
     * Fetch the principal from the database -- also fetch the key data.
     * Note that since this retrieves the key data, it has to be linked with
     * the kadm5srv library.
     */

    if ((retcode = kadm5_get_principal(handle, princ, p,
				       KADM5_PRINCIPAL_NORMAL_MASK |
				       KADM5_KEY_DATA))) {
	if (retcode == KADM5_UNK_PRINC) {
	    krb5_free_principal(context, princ);
	    syslog(LOG_INFO, "principal %s.%s does not exist", name, inst);
	    return KANOENT;
	} else {
	    krb5_free_principal(context, princ);
	    syslog(LOG_ERR, "kadm5_get_principal failed: %s",
		   error_message(retcode));
	    return KAINTERNALERROR;
	}
    }

    krb5_free_principal(context, princ);

    /*
     * Check various things - taken from the KDC code.
     *
     * Since we're essentially bypassing the KDC, we need to make sure
     * that we don't give out a ticket that we shouldn't.
     */

    /*
     * Has the principal expired?
     */

    if (p->princ_expire_time && p->princ_expire_time < req_time) {
	kadm5_free_principal_ent(handle, p);
	return KABADUSER;
    }

    /*
     * Has the principal's password expired?  Note that we don't
     * check for the PWCHANGE_SERVICE flag here, since we don't
     * support password changing.  We do support the REQUIRES_PWCHANGE
     * flag, though.
     */

    if ((p->pw_expiration && p->pw_expiration < req_time) ||
	(p->attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
	kadm5_free_principal_ent(handle, p);
	return KABADUSER;
    }

    /*
     * See if the principal is locked out
     */

    if (p->attributes & KRB5_KDB_DISALLOW_ALL_TIX) {
	kadm5_free_principal_ent(handle, p);
	return KABADUSER;
    }

    /*
     * There's no way we can handle hardware preauth, so
     * disallow tickets with this flag set.
     */

    if (p->attributes & KRB5_KDB_REQUIRES_HW_AUTH) {
	kadm5_free_principal_ent(handle, p);
	return KABADUSER;
    }

    /*
     * Must be okay, then
     */

    return 0;
}


/*
 * Create an rx reply packet in "packet" using the provided data.
 * The caller is responsible for zeroing key and sched.
 */

int make_reply_packet(context, handle, reply, challenge_response, start_time,
		      end_time, cname, cinst, sname, sinst, key, sched, label)
krb5_context context;
void *handle;
packet_t reply;
int challenge_response, start_time, end_time;
char *cname, *cinst, *sname, *sinst;
des_cblock key;
des_key_schedule sched;
char *label;
{
    int rv, n, maxn, v4life, *enclenp, *ticklenp;
    u_char *p, *enc, *ticket;
    kadm5_principal_ent_rec cprinc, sprinc;
    des_cblock skey, new_session_key;
    des_key_schedule ssched;
    krb5_deltat lifetime;

    rv = 0;

    rv = check_princ(context, handle, cname, cinst, &cprinc);
    if (rv)
	return rv;

    rv = check_princ(context, handle, sname, sinst, &sprinc);
    if (rv) {
	kadm5_free_principal_ent(handle, &cprinc);
	return rv;
    }

    /* 
     * Bound ticket lifetime by max lifetimes of user and service.
     *
     * Since V5 already stores everything in Unix epoch timestamps like
     * AFS, these calculations are much simpler.
     */

    lifetime = end_time - start_time;
    lifetime = min(lifetime, cprinc.max_life);
    lifetime = min(lifetime, sprinc.max_life);
    lifetime = min(lifetime, realm_params.max_life);

    end_time = start_time + lifetime;

    /*
     * But we have to convert back to V4-style lifetimes
     */

    v4life = lifetime / 300;
    if (v4life > 127) {
	/*
	 * Use the CMU algorithm instead
	 */
	long *clist = cmu_seconds;
	while (*clist && *clist < lifetime) clist++;
	v4life = 128 + (clist - cmu_seconds);
    }

    /*
     * If this is for afs and the instance is the local cell name
     * then we assume we added the instance in GetTickets to
     * identify the afs key in the kerberos database. This is for
     * cases where the afs cell name is different from the kerberos
     * realm name. We now want to remove the instance so it doesn't
     * cause klog to barf.
     */
    if (!strcmp(sname, "afs") && (strcasecmp(sinst, localcell) == 0))
	sinst[0] = '\0';

    /*
     * All the data needed to construct the ticket is ready, so do it.
     */

    p = (unsigned char *) reply->base;
    maxn = reply->len;
    n = 0;

#define ERR(x) do { rv = x ; goto error; } while (0)
#define ADVANCE(x) { if ((n += x) > maxn) ERR(KAINTERNALERROR); else p += x;}
#define PUT_CHAR(x) { *p = (x); ADVANCE(1); }
#define PUT_INT(x) { int q = ntohl(x); memcpy(p, (char *)&q, 4); ADVANCE(4); }
#define PUT_STR(x) { strcpy((char *) p, x); ADVANCE(strlen(x) + 1); }

    ADVANCE(28);
    PUT_INT(0x2bc);

    enclenp = (int *)p;
    PUT_INT(0);		/* filled in later */

    enc = p;
    PUT_INT(0);
    PUT_INT(challenge_response);

    /*
     * new_session_key is created here, and remains in the clear
     * until just before we return.
     */
    des_new_random_key(new_session_key);
    memcpy(p, new_session_key, 8);

    ADVANCE(8);
    PUT_INT(start_time);
    PUT_INT(end_time);
    PUT_INT(sprinc.kvno);

    ticklenp = (int *)p;
    PUT_INT(0);		/* filled in later */

    PUT_STR(cname);
    PUT_STR(cinst);
    PUT_STR("");
    PUT_STR(sname);
    PUT_STR(sinst);

    ticket = p;
    PUT_CHAR(0);	/* flags, always 0 */
    PUT_STR(cname);
    PUT_STR(cinst);
    PUT_STR("");
    PUT_INT(0);		/* would be ip address */

    memcpy(p, new_session_key, 8);

    ADVANCE(8);

    PUT_CHAR(v4life);
    PUT_INT(start_time);
    PUT_STR(sname);
    PUT_STR(sinst);

    ADVANCE(PAD_TO(p - ticket, 8) - (p - ticket));

    *ticklenp = ntohl(p - ticket);

    rv = get_princ_key(context, handle, &sprinc, skey, ssched);
    if (rv)
	return rv;
    des_pcbc_encrypt((C_Block *) ticket, (C_Block *) ticket, p - ticket,
		     ssched, (C_Block *) skey, ENCRYPT);
    memset(skey, 0, sizeof(skey));
    memset(ssched, 0, sizeof(ssched));

    PUT_STR(label);	/* "tgsT" or "gtkt" */
    ADVANCE(-1);	/* back up over string terminator */

    ADVANCE(PAD_TO(p - enc, 8) - (p - enc));
#undef	ERR
#undef	ADVANCE
#undef	PUT_CHAR
#undef	PUT_INT
#undef	PUT_STR

    *enclenp = ntohl(p - enc);
    des_pcbc_encrypt((C_Block *) enc, (C_Block *) enc, p - enc, sched,
		     (C_Block *) key, ENCRYPT);
    reply->len = n;

  error:
    memset(new_session_key, 0, sizeof(new_session_key));
    kadm5_free_principal_ent(handle, &cprinc);
    kadm5_free_principal_ent(handle, &sprinc);

    return rv;
}

#define ERR(x) do { rv = x; goto error; } while (0)
#define ADVANCE(x) { if ((n += x) > maxn) ERR(KABADREQUEST); else p += x; }
#define GET_INT(x) { int q; memcpy((char *)&q, p, 4); x = ntohl(q); ADVANCE(4); }
#define GET_CHAR(x) { x = *p; ADVANCE(1); }
#define GET_PSTR(x) \
    { \
	GET_INT(len); \
	if (len > sizeof(x) - 1) ERR(KABADREQUEST); \
	memcpy(x, p, len); \
	x[len] = 0; \
	ADVANCE(PAD_TO(len, 4)); \
    }

#define GET_STR(x) \
    { \
	len = strlen(p); \
	if (len > sizeof(x) - 1) ERR(KABADREQUEST); \
	strcpy(x, p); \
	ADVANCE(len + 1); \
    }


/*
 * Process an Authenticate request.
 */

int Authenticate(context, handle, from, req, reply)
krb5_context context;
void *handle;
char *from;
packet_t req, reply;
{
    int rv, n, maxn;
    int len, start_time, end_time, challenge;
    char name[ANAME_SZ+1], inst[INST_SZ+1], *p;
    kadm5_principal_ent_rec cprinc;
    des_cblock ckey;
    des_key_schedule csched;
    int free_princ_ent = 0;

    rv = 0;

    p = req->base;
    maxn = req->len;
    n = 0;

    ADVANCE(32);

    GET_PSTR(name);
    GET_PSTR(inst);

    if (debug)
	fprintf(stderr, "Authenticating %s.%s\n", name, inst);

    rv = check_princ(context, handle, name, inst, &cprinc);
    if (rv)
	ERR(rv);

    free_princ_ent = 1;

    GET_INT(start_time);
    GET_INT(end_time);

    GET_INT(len);
    if (len != 8)
	ERR(KABADREQUEST);

    /*
     * ckey and csched are set here and remain in the clear
     * until just before we return.
     */

    rv = get_princ_key(context, handle, &cprinc, ckey, csched);
    if (rv)
	ERR(rv);
    des_pcbc_encrypt((C_Block *) p, (C_Block *) p, 8, csched,
		     (C_Block *) ckey, DECRYPT);

    GET_INT(challenge);

    rv = memcmp(p, "gTGS", 4);
    if (rv)
	ERR(KABADREQUEST);
    ADVANCE(4);

    /* ignore the rest */
    ADVANCE(8);

    /*
     * We have all the data from the request, now generate the reply.
     */

    rv =  make_reply_packet(context, handle, reply, challenge + 1, start_time,
   			    end_time, name, inst, "krbtgt", localcell,
			    ckey, csched, "tgsT");
  error:
    memset(ckey, 0, sizeof(ckey));
    memset(csched, 0, sizeof(csched));

    syslog(LOG_INFO, "authenticate: %s.%s from %s", name, inst, from);
    if (rv) {
	syslog(LOG_INFO, "... failed due to %s", kaerror(rv));
    }
    if (free_princ_ent)
	kadm5_free_principal_ent(handle, &cprinc);
    return rv;
}


/*
 * Process a GetTicket rpc.
 */

int GetTicket(context, handle, from, req, reply)
krb5_context context;
void *handle;
char *from;
packet_t req, reply;
{
    int rv, n, maxn, len, ticketlen;
    char *p;
    u_int kvno, start_time, end_time, times[2], flags, ipaddr;
    u_int tgt_start_time, tgt_end_time, lifetime;
    char rname[ANAME_SZ+1], rinst[INST_SZ+1];	/* requested principal */
    char sname[ANAME_SZ+1], sinst[INST_SZ+1];	/* service principal (TGT) */
    char cname[ANAME_SZ+1], cinst[INST_SZ+1];	/* client principal */
    char cell[REALM_SZ+1], realm[REALM_SZ+1];
    char enctimes[8 + 1], ticket[1024];
    u_char tgt_lifetime;
    kadm5_principal_ent_rec cprinc;
    des_cblock ckey, session_key;
    des_key_schedule csched, session_sched;
    int free_princ_ent = 0;

    rv = 0;

    /* 
     * Initialize these so we don't crash trying to print them in
     * case they don't get filled in.
     */
    strlcpy(rname, "Unknown", sizeof(rname));
    strlcpy(rinst, "Unknown", sizeof(rinst));
    strlcpy(sname, "Unknown", sizeof(sname));
    strlcpy(sinst, "Unknown", sizeof(sinst));
    strlcpy(cname, "Unknown", sizeof(cname));
    strlcpy(cinst, "Unknown", sizeof(cinst));
    strlcpy(cell, "Unknown", sizeof(cell));
    strlcpy(realm, "Unknown", sizeof(realm));
    
    p = req->base;
    maxn = req->len;
    n = 0;

    ADVANCE(32);

    GET_INT(kvno);

    GET_PSTR(cell);
    if (!cell[0])
      strlcpy(cell, localcell, sizeof(cell));

    if (debug)
	fprintf(stderr, "Cell is %s\n", cell);

    memset(ticket, 0, sizeof(ticket));
    GET_PSTR(ticket);
    ticketlen = len;	/* hacky hack hack */
    GET_PSTR(rname);
    GET_PSTR(rinst);

    if (debug)
	fprintf(stderr, "Request for %s/%s\n", rname, rinst);

    GET_PSTR(enctimes);	/* still encrypted */
    if (len != 8)	/* hack and hack again */
	ERR(KABADREQUEST);

    /* ignore the rest */
    ADVANCE(8);

    /*
     * That's it for the packet, now decode the embedded ticket.
     */

    rv = check_princ(context, handle, "krbtgt", cell, &cprinc);
    if (rv)
	ERR(rv);

    free_princ_ent = 1;

    rv = get_princ_key(context, handle, &cprinc, ckey, csched);
    if (rv)
	ERR(rv);
    des_pcbc_encrypt((C_Block *) ticket, (C_Block *) ticket, ticketlen, csched,
		     (C_Block *) ckey, DECRYPT);
    memset(ckey, 0, sizeof(ckey));
    memset(csched, 0, sizeof(csched));

    /*
     * The ticket's session key is now in the clear in the ticket buffer.
     * We zero it just before returning.
     */

    p = ticket;
    maxn = ticketlen;
    n = 0;

    GET_CHAR(flags);
    GET_STR(cname);
    GET_STR(cinst);
    GET_STR(realm);
    GET_INT(ipaddr);
    memcpy(session_key, p, 8);
    ADVANCE(8);

    GET_CHAR(tgt_lifetime);
    GET_INT(tgt_start_time);
    GET_STR(sname);
    GET_STR(sinst);

    if (debug)
	fprintf(stderr,
		"ticket: %s.%s@%s for %s.%s\n",
		cname, cinst, realm, sname, sinst);

    /*
     * ok, we've got the ticket unpacked.
     * now decrypt the start and end times.
     */

    rv = des_key_sched(session_key, session_sched);
    if (rv) 
	ERR(KABADTICKET);

    des_ecb_encrypt((C_Block *) enctimes, (C_Block *) times, session_sched,
		    DECRYPT);
    start_time = ntohl(times[0]);
    end_time = ntohl(times[1]);

    /*
     * All the info we need is now available.
     * Now validate the request.
     */

    /*
     * This translator requires that the flags and IP address
     * in the ticket be zero, because we always set them that way,
     * and we want to accept only tickets that we generated.
     * 
     * Are the flags and IP address fields 0?
     */
    if (flags || ipaddr) {
	if (debug)
	    fprintf(stderr, "ERROR: flags or ipaddr field non-zero\n");
	ERR(KABADTICKET);
    }
    /*
     * Is the supplied ticket a tgt?
     */
    if (strcmp(sname, "krbtgt")) {
	if (debug)
	    fprintf(stderr, "ERROR: not for krbtgt service\n");
	ERR(KABADTICKET);
    }

    /*
     * This translator does not allow MIT-style cross-realm access.
     * Is this a cross-realm ticket?
     */
    if (strcasecmp(sinst, localcell)) {
	if (debug)
	    fprintf(stderr,
		    "ERROR: Service instance (%s) differs from local cell\n",
		    sinst);
	ERR(KABADTICKET);
    }

    /*
     * This translator does not issue cross-realm tickets,
     * since klog doesn't use this feature.
     * Is the request for a cross-realm ticket?
     */
    if (strcasecmp(cell, localcell)) {
	if (debug)
	    fprintf(stderr, "ERROR: Cell %s != local cell", cell);
	ERR(KABADTICKET);
    }

    /*
     * Even if we later decide to issue cross-realm tickets,
     * we should not permit "realm hopping".
     * This means that the client's realm should match
     * the realm of the tgt with whose key we are supposed
     * to decrypt the ticket.  I think.
     */
    if (*realm && strcasecmp(realm, cell)) {
	if (debug)
	    fprintf(stderr, "ERROR: Realm %s != cell %s\n", realm, cell);
	ERR(KABADTICKET);
    }

    /*
     * This translator issues service tickets only for afs,
     * since klog is the only client that should be using it.
     * Is the requested service afs?
     *
     * Note: to make EMT work, we're allowing tickets for emt/admin and
     * adm/admin.
     */
    if (! ((strcmp(rname, "afs") == 0 && ! *rinst) ||
	   (strcmp(rname, "emt") == 0 && strcmp(rinst, "admin") == 0) ||
	   (strcmp(rname, "adm") == 0 && strcmp(rinst, "admin") == 0)))
	ERR(KABADSERVER);

    /*
     * If the local realm name and cell name differ and the user
     * is in the local cell and has requested a ticket of afs. (no
     * instance, then we actually want to get a ticket for
     * afs/<cell name>@<realm name>
     */
    if ((strcmp(rname, "afs") == 0) && !*rinst &&
	strcmp(localrealm, localcell) &&
	(strcasecmp(cell, localcell) == 0)) {
	char *c;

	strlcpy(rinst, localcell, sizeof(rinst));

	for (c = rinst; *c != NULL; c++)
	    *c = (char) tolower( (int) *c);

	if (debug)
	    fprintf(stderr, "Getting ticket for afs/%s\n", localcell);
    }
   
    /*
     * Even if we later decide to issue service tickets for
     * services other than afs, we should still disallow
     * the "changepw" and "krbtgt" services.
     */
    if (!strcmp(rname, "changepw") || !strcmp(rname, "krbtgt"))
	ERR(KABADSERVER);

    /*
     * Is the tgt valid yet?  (ie. is the start time in the future)
     */
    if (req_time < tgt_start_time - CLOCK_SKEW) {
	if (debug)
	    fprintf(stderr, "ERROR: Ticket not yet valid\n");
	ERR(KABADTICKET);
    }

    /*
     * Has the tgt expired?  (ie. is the end time in the past)
     *
     * Sigh, convert from V4 lifetimes back to Unix epoch times.
     */

    if (tgt_lifetime < 128)
	tgt_end_time = tgt_start_time + tgt_lifetime * 300;
    else if (tgt_lifetime < 192)
	tgt_end_time = tgt_start_time + cmu_seconds[tgt_lifetime - 128];
    else
	tgt_end_time = tgt_start_time + MAX_TICKET_LIFETIME;

    if (tgt_end_time < req_time) {
	if (debug)
	    fprintf(stderr, "ERROR: Ticket expired\n");
	ERR(KABADTICKET);
    }

    /*
     * This translator uses the requested start time as a cheesy
     * authenticator, since the KA protocol does not have an
     * explicit authenticator.  We can do this since klog always
     * requests a start time equal to the current time.
     * 
     * Is the requested start time approximately now?
     */
    if (abs(req_time - start_time) > CLOCK_SKEW)
	ERR(KACLOCKSKEW);

    /*
     * The new ticket's lifetime is the minimum of:
     * 1.  remainder of tgt's lifetime
     * 2.  requested lifetime
     * 
     * This is further limited by the client and service's max lifetime
     * in make_reply_packet().
     */

    lifetime = tgt_end_time - req_time;
    lifetime = min(lifetime, end_time - start_time);
    end_time = req_time + lifetime;

    /*
     * We have all the data from the request, now generate the reply.
     */

    rv = make_reply_packet(context, handle, reply, 0, start_time, end_time,
			   cname, cinst, rname, rinst,
			   session_key, session_sched, "gtkt");
  error:
    memset(ticket, 0, sizeof(ticket));
    memset(session_key, 0, sizeof(session_key));
    memset(session_sched, 0, sizeof(session_sched));

    if (free_princ_ent)
	kadm5_free_principal_ent(handle, &cprinc);

    syslog(LOG_INFO, "getticket: %s.%s from %s for %s.%s",
	   cname, cinst, from, rname, rinst);
    if (rv) {
	syslog(LOG_INFO, "... failed due to %s", kaerror(rv));
    }
    return rv;
}


#undef	ERR
#undef	ADVANCE
#undef	GET_INT
#undef	GET_PSTR
#undef	GET_STR

/*
 * Convert the request into a reply.
 * Returns 0 on success.
 */

void process(context, handle, from, req, reply)
krb5_context context;
void *handle;
char *from;
packet_t req, reply;
{
    int rv;
    rx_t req_rx = (rx_t)req->base;
    rx_t reply_rx = (rx_t)reply->base;
    int service, request;

    service = ntohs(req_rx->rx_service);
    request = ntohl(req_rx->rx_request);

    /* ignore everything but type 1 */
    if (req_rx->rx_type != 1) {
	reply->len = 0;
	return;
    }

    /* copy the rx header and change the flags */
    *reply_rx = *req_rx;
    reply_rx->rx_flags = 4;

    rv = -1;

    if (service == 0x2db && (request == 0x15 || request == 0x16)) {
	if (debug)
	    fprintf(stderr, "Handling Authenticate request\n");
	rv = Authenticate(context, handle, from, req, reply);
    }
    if (service == 0x2dc && request == 0x17) {
	if (debug)
	    fprintf(stderr, "Handling GetTicket request\n");
	rv = GetTicket(context, handle, from, req, reply);
    }
/*
    if (service == 0x2db && request == 0x1) {
	rv = Authenticate_old(from, req, reply);
    }
    if (service == 0x2dc && request == 0x3) {
	rv = GetTicket_old(from, req, reply);
    }
 */
    if (rv == -1) {
	syslog(LOG_INFO, "bogus request %d/%d", service, request);
	rv = KABADREQUEST;
    }

    if (rv) {
	/* send the error back to rx */
	reply->len = sizeof (*reply_rx);

	reply_rx->rx_type = 4;
	reply_rx->rx_flags = 0;
	reply_rx->rx_request = ntohl(rv);
    }
}


int main(argc, argv)
int argc;
char **argv;
{
    int s, rv, ch, mflag = 0;
    u_short port;
    struct sockaddr_in sin;
    int forwarders[MAXFORWARDERS], num_forwarders;
    krb5_context context;
    krb5_error_code code;
    krb5_keyblock mkey;
    krb5_principal master_princ;
    kadm5_principal_ent_rec master_princ_rec;
    void *handle;
    facility_mapping *mapping;
    int facility = LOG_DAEMON;

    extern char *optarg;

    port = 7004;
    num_forwarders = 0;

    /*
     * Parse args.
     */
    while ((ch = getopt(argc, argv, "c:df:l:mp:r:")) != -1) {
	switch (ch) {
	case 'c':
	    localcell = optarg;
	    break;
	case 'd':
	    debug++;
	    break;
	case 'f': {
	    struct hostent *hp;

	    if (num_forwarders++ >= MAXFORWARDERS)
		pexit("too many forwarders\n");

	    hp = gethostbyname(optarg);
	    if (!hp) {
		printf("unknown host %s\n", optarg);
		exit(1);
	    }
	    forwarders[num_forwarders - 1] = *(int *)hp->h_addr;

	    break;
	}
	case 'l':
	    for (mapping = mappings; mapping->string != NULL; mapping++)
		if (strcmp(mapping->string, optarg) == 0)
		    break;

		if (mapping->string == NULL) {
		    printf("Unknown facility \"%s\"\n", optarg);
		    exit(1);
		}

		facility = mapping->num;
		break;
	case 'm':
	    mflag = 1;
	    break;
	case 'p':
	    if (isdigit(*optarg)) {
		port = atoi(optarg);
	    }
	    else {
		struct servent *sp;

		sp = getservbyname(optarg, "udp");
		if (!sp) {
		    printf("unknown service %s\n", optarg);
		    exit(1);
		}
		port = sp->s_port;
	    }
	    break;
	case 'r':
	    localrealm = optarg;
	    break;
	default:
	    printf("usage: %s [-c cell] [-d] [-f forwarder-host] [-l facility ] [-p port] [-r realm]\n",
		   argv[0]);
	    exit(1);
	}
    }

    openlog("fakeka", LOG_PID, facility);

    port = htons(port);

    /*
     * Set up the socket.
     */

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
	perrorexit("Couldn't create socket");
    set_cloexec_fd(s);

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = port;

    rv = bind(s, (struct sockaddr *)&sin, sizeof(sin));
    if (rv < 0)
	perrorexit("Couldn't bind socket");

    /*
     * Initialize kerberos stuff and kadm5 stuff.
     */

    if ((code = krb5int_init_context_kdc(&context))) {
	com_err(argv[0], code, "while initializing Kerberos");
	exit(1);
    }

    if (!localrealm && (code = krb5_get_default_realm(context, &localrealm))) {
	com_err(argv[0], code, "while getting local realm");
	exit(1);
    }

    if (!localcell)
	localcell = localrealm;

    if ((code = kadm5_init_with_password(progname, NULL, KADM5_ADMIN_SERVICE,
					 NULL, KADM5_STRUCT_VERSION,
					 KADM5_API_VERSION_2,
					 (char **) NULL, /* db_args */
					 &handle))) {
	com_err(argv[0], code, "while initializing Kadm5");
	exit(1);
    }

    if ((code = kadm5_get_config_params(context, 1, NULL,
					&realm_params))) {
	com_err(argv[0], code, "while getting realm parameters");
	exit(1);
    }

    if (! (realm_params.mask & KADM5_CONFIG_MAX_LIFE)) {
	fprintf(stderr, "Cannot determine maximum ticket lifetime\n");
	exit(1);
    }

    /*
     * We need to initialize the random number generator for DES.  Use
     * the master key to do this.
     */

    if ((code = krb5_parse_name(context, realm_params.mask &
				KADM5_CONFIG_MKEY_NAME ?
				realm_params.mkey_name : "K/M",
				&master_princ))) {
	com_err(argv[0], code, "while parsing master key name");
	exit(1);
    }

    if ((code = kadm5_get_principal(handle, master_princ, &master_princ_rec,
				    KADM5_KEY_DATA))) {
	com_err(argv[0], code, "while getting master key data");
	exit(1);
    }

    if ((code = kadm5_decrypt_key(handle, &master_princ_rec,
				  ENCTYPE_DES_CBC_CRC, -1, 0, &mkey, NULL,
				  NULL))) {
	com_err(argv[0], code, "while decrypting the master key");
	exit(1);
    }

    des_init_random_number_generator(mkey.contents);

    krb5_free_keyblock_contents(context, &mkey);

    kadm5_free_principal_ent(handle, &master_princ_rec);

    krb5_free_principal(context, master_princ);

    /*
     * Fork and go into the background, if requested
     */

    if (!debug && mflag && daemon(0, 0)) {
	com_err(argv[0], errno, "while detaching from tty");
    }

    /*
     * rpc server loop.
     */

    for (;;) {
	struct packet req, reply;
	int sinlen, packetlen, i, forwarded;
	char *from;

	sinlen = sizeof(sin);
	forwarded = 0;

	memset(req.data, 0, sizeof(req.data));
	rv = recvfrom(s, req.data, sizeof(req.data),
		      0, (struct sockaddr *)&sin, &sinlen);

	if (rv < 0) {
	    syslog(LOG_ERR, "recvfrom failed: %m");
	    sleep(1);
	    continue;
	}
	packetlen = rv;

	for (i = 0; i < num_forwarders; i++) {
	    if (sin.sin_addr.s_addr == forwarders[i]) {
		forwarded = 1;
		break;
	    }
	}

	if ((code = krb5_timeofday(context, &req_time))) {
		syslog(LOG_ERR, "krb5_timeofday failed: %s",
		       error_message(code));
		continue;
	}

	memset(reply.data, 0, sizeof(reply.data));
	req.len = packetlen;
	req.base = req.data;
	reply.base = reply.data;
	reply.len = sizeof(reply.data);

	if (forwarded) {
	    struct in_addr ia;

	    memcpy(&ia.s_addr, req.data, 4);
	    from = inet_ntoa(ia);
	    /*
	     * copy the forwarder header and adjust the bases and lengths.
	     */
	    memcpy(reply.data, req.data, HEADER_LEN);
	    req.base += HEADER_LEN;
	    req.len -= HEADER_LEN;
	    reply.base += HEADER_LEN;
	    reply.len -= HEADER_LEN;
	}
	else {
	    from = inet_ntoa(sin.sin_addr);
	}

	process(context, handle, from, &req, &reply);

	if (reply.len == 0)
	    continue;

	if (forwarded) {
	    /* re-adjust the length to account for the forwarder header */
	    reply.len += HEADER_LEN;
	}

	rv = sendto(s, reply.data, reply.len,
		    0, (struct sockaddr *)&sin, sinlen);
	if (rv < 0) {
	    syslog(LOG_ERR, "sendto failed: %m");
	    sleep(1);
	}
    }
    /*NOTREACHED*/
}
