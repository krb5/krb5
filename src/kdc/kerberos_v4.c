/*
 * kdc/kerberos_v4.c
 *
 * Copyright 1985, 1986, 1987, 1988,1991,2007 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */

#include "autoconf.h"
#ifdef KRB5_KRB4_COMPAT
#define BACKWARD_COMPAT

#include "k5-int.h"
#include "kdc_util.h"
#include "adm_proto.h"

#include <stdarg.h>

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif
#include <sys/file.h>
#include <ctype.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

/* v4 include files:
 */
#include <krb.h>
#include <des.h>
#include <klog.h>
#include <prot.h>
#include <krb_db.h>

#ifdef NEED_SWAB_PROTO
extern void swab(const void *, void *, size_t );
#endif

static int compat_decrypt_key (krb5_key_data *, C_Block,
					 krb5_keyblock *, int);
static int kerb_get_principal (char *, char *, Principal *,
					 int *, krb5_keyblock *, krb5_kvno,
					 int, krb5_deltat *);
static int check_princ (char *, char *, int, Principal *,
				  krb5_keyblock *, int, krb5_deltat *);

static char * v4_klog (int, const char *, ...)
#if !defined(__cplusplus) && (__GNUC__ > 2)
    __attribute__((__format__(__printf__, 2, 3)))
#endif
    ;
#define klog v4_klog

/* Byte ordering */
/*#define		MSB_FIRST		0	/ * 68000, IBM RT/PC */
/*#define		LSB_FIRST		1	/ * Vax, PC8086 */
#if defined K5_LE
# define HOST_BYTE_ORDER 1
#elif defined K5_BE
# define HOST_BYTE_ORDER 0
#else
static int krbONE = 1;
# define HOST_BYTE_ORDER (* (char *) &krbONE)
#endif

#ifndef BACKWARD_COMPAT
static Key_schedule master_key_schedule;
static C_Block master_key;
#endif

static struct timeval kerb_time;
static Principal a_name_data;	/* for requesting user */
static Principal s_name_data;	/* for services requested */
static C_Block session_key;

static char log_text[512];
static char *lt;

/* fields within the received request packet */
static u_char req_msg_type;
static u_char req_version;
static char *req_name_ptr;
static char *req_inst_ptr;
static char *req_realm_ptr;

static krb5_ui_4 req_time_ws;

static char local_realm[REALM_SZ];

static long n_auth_req;
static long n_appl_req;

static long pause_int = -1;

static void hang(void);


/* v4/v5 backwards-compatibility stub routines,
 * which allow the v5 server to handle v4 packets
 * by invoking substantially-unaltered v4 server code.
 * this is only necessary during the installation's conversion to v5.
 * process_v4() is invoked by v5's dispatch() routine;
 * when the v4 server needs to access the v5 database,
 * it calls the other stubs.
 *
 * until all kerberized application-programs are updated,
 * this approach inflates the v5 server's code size,
 * but it's easier to debug than a concurrent, subordinate v4 server would be.
 */

/*
 * v5 include files:
 */
#include "com_err.h"
#include "extern.h"		/* to pick up master_princ */

static krb5_data *kerberos_v4 (struct sockaddr_in *, KTEXT);
static krb5_data *kerb_err_reply (struct sockaddr_in *, KTEXT, long, char *);
static int set_tgtkey (char *, krb5_kvno, krb5_boolean);

/* Attributes converted from V5 to V4 - internal representation */
#define V4_KDB_REQUIRES_PREAUTH  0x1
#define V4_KDB_DISALLOW_ALL_TIX  0x2
#define V4_KDB_REQUIRES_PWCHANGE 0x4
#define V4_KDB_DISALLOW_SVR      0x8

/* v4 compatibitly mode switch */
#define KDC_V4_NONE		0	/* Don't even respond to packets */
#define KDC_V4_DISABLE		1	/* V4 requests return an error */
#define	KDC_V4_FULL		2	/* Preauth required go through */
#define KDC_V4_NOPREAUTH	3	/* Preauth required disallowed */

#define KDC_V4_DEFAULT_MODE KDC_V4_NONE
/* Flag on how to handle v4 */
static int		kdc_v4;

struct v4mode_lookup_entry {
    int                 mode;                   /* Mode setting */
    const char *	v4_specifier;		/* How to recognize it	*/
};

static const struct v4mode_lookup_entry  v4mode_table[] = {
/*  mode                input specifier */
{ KDC_V4_NONE,          "none"          },
{ KDC_V4_DISABLE,       "disable"       }, 
{ KDC_V4_FULL,          "full"          },
{ KDC_V4_NOPREAUTH,     "nopreauth"     }
};

static const int v4mode_table_nents = sizeof(v4mode_table)/
				      sizeof(v4mode_table[0]);

static int allow_v4_crossrealm = 0;

void process_v4_mode(const char *program_name, const char *string)
{
    int i, found;

    found = 0;
    kdc_v4 = KDC_V4_DEFAULT_MODE;

    if(!string) return;  /* Set to default mode */
    
    for (i=0; i<v4mode_table_nents; i++) {
	if (!strcasecmp(string, v4mode_table[i].v4_specifier)) {
	    found = 1;
	    kdc_v4 = v4mode_table[i].mode;
	    break;
	}
    }

    if(!found) {
      /* It is considered fatal if we request a mode that is not found */
	com_err(program_name, 0, "invalid v4_mode %s", string);
	exit(1);
    }
    return;
}

void enable_v4_crossrealm ( char *programname) {
    allow_v4_crossrealm = 1;
    krb5_klog_syslog(LOG_ERR, "Enabling v4 cross-realm compatibility; this is a known security hole");
}

krb5_error_code
process_v4(const krb5_data *pkt, const krb5_fulladdr *client_fulladdr,
	   krb5_data **resp)
{
    struct sockaddr_in client_sockaddr;
    krb5_address *addr = client_fulladdr->address;
    krb5_error_code retval;
    krb5_timestamp now;
    KTEXT_ST v4_pkt;
    char *lrealm;

    /* Check if disabled completely */
    if (kdc_v4 == KDC_V4_NONE) {
	(void) klog(L_KRB_PERR, "Disabled KRB V4 request");
	return KRB5KDC_ERR_BAD_PVNO;
    }

    
    if ((retval = krb5_timeofday(kdc_context, &now)))
        return(retval);
    kerb_time.tv_sec = now;

    if (!*local_realm) {		/* local-realm name already set up */
	lrealm = master_princ->realm.data;
	if (master_princ->realm.length < sizeof(local_realm)) {
	    memcpy(local_realm, lrealm, master_princ->realm.length);
	    local_realm[master_princ->realm.length] = '\0';
	} else
	    retval = KRB5_CONFIG_NOTENUFSPACE;
    }
    /* convert client_fulladdr to client_sockaddr:
     */
    client_sockaddr.sin_family	= AF_INET;
    client_sockaddr.sin_port	= client_fulladdr->port;
    if (client_fulladdr->address->addrtype != ADDRTYPE_INET) {
	klog(L_KRB_PERR, "got krb4 request from non-ipv4 address");
	client_sockaddr.sin_addr.s_addr = 0;
    } else
	memcpy(&client_sockaddr.sin_addr, addr->contents, 
	       sizeof client_sockaddr.sin_addr);
    memset( client_sockaddr.sin_zero, 0, sizeof client_sockaddr.sin_zero);

    /* convert v5 packet structure to v4's.
     * this copy is gross, but necessary:
     */
    if (pkt->length > MAX_KTXT_LEN) {
	    (void) klog(L_KRB_PERR, "V4 request too long.");
	    return KRB5KRB_ERR_FIELD_TOOLONG;
    }
    memset( &v4_pkt, 0, sizeof(v4_pkt));
    v4_pkt.length = pkt->length;
    v4_pkt.mbz = 0;
    memcpy( v4_pkt.dat, pkt->data, pkt->length);

    *resp = kerberos_v4( &client_sockaddr, &v4_pkt);
    return(retval);
}

static char * v4_klog( int type, const char *format, ...)
{
    int logpri = LOG_INFO;
    va_list pvar;
    va_start(pvar, format);

    switch (type) {
    case L_ERR_SEXP:
    case L_ERR_NKY:
    case L_ERR_NUN:
    case L_ERR_UNK:
    case L_KRB_PERR:
	logpri = LOG_ERR;
    case L_INI_REQ:
    case L_NTGT_INTK:
    case L_TKT_REQ:
    case L_APPL_REQ:
	strlcpy(log_text, "PROCESS_V4:", sizeof(log_text));
	vsnprintf(log_text+strlen(log_text),
		  sizeof(log_text) - strlen(log_text),
		  format, pvar);
	krb5_klog_syslog(logpri, "%s", log_text);
    default:
	/* ignore the other types... */
	;
    }
    va_end(pvar);
    return(log_text);
}

static
krb5_data *make_response(const char *msg, int len)
{
    krb5_data *response;

    if (  !(response = (krb5_data *) malloc( sizeof *response))) {
	return 0;
    }
    if ( !(response->data = (char *) malloc( len))) {
	krb5_free_data(kdc_context,  response);
	return 0;
    }
    response->length = len;
    memcpy( response->data, msg, len);
    return response;
}
static void
hang(void)
{
    if (pause_int == -1) {
        klog(L_KRB_PERR, "Kerberos will pause so as not to loop init");
     /* for (;;)
            pause(); */
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf),
	   "Kerberos will wait %d seconds before dying so as not to loop init",
		(int) pause_int);
        klog(L_KRB_PERR, buf);
        sleep((unsigned) pause_int);
        klog(L_KRB_PERR, "Do svedania....\n");
     /* exit(1); */
    }
}
#define kdb_encrypt_key( in, out, mk, mks, e_d_flag)
#define LONGLEN 4
#define K4KDC_ENCTYPE_OK(e)			\
((e) == ENCTYPE_DES_CBC_CRC			\
 || (e) == ENCTYPE_DES_CBC_MD4			\
 || (e) == ENCTYPE_DES_CBC_MD5			\
 || (e) == ENCTYPE_DES_CBC_RAW)

/* take a v5 keyblock, masquerading as a v4 key,
 * decrypt it, and convert the resulting v5 keyblock
 * to a real v4 key.
 * this is ugly, but it saves changing more v4 code.
 *
 * Also, keep old krb5_keyblock around in case we want to use it later.
 */
static int
compat_decrypt_key (krb5_key_data *in5, unsigned char *out4,
		    krb5_keyblock *out5, int issrv)
{
    krb5_error_code retval;

    out5->contents = NULL;
    memset(out4, 0, sizeof(out4));
    retval = krb5_dbekd_decrypt_key_data(kdc_context, &master_keyblock,
					 in5, out5, NULL);
    if (retval) {
	lt = klog(L_DEATH_REQ, "KDC can't decrypt principal's key.");
	out5->contents = NULL;
	return(retval);
    }
    if (K4KDC_ENCTYPE_OK(out5->enctype)) {
	if (out5->length == KRB5_MIT_DES_KEYSIZE) 
	    memcpy(out4, out5->contents, out5->length);
	else {
	    lt = klog(L_DEATH_REQ, "internal keysize error in kdc");
	    krb5_free_keyblock_contents(kdc_context, out5);
	    out5->contents = NULL;
	    retval = -1;
	}
    } else {
	if (!issrv) {
	    lt = klog(L_DEATH_REQ, "incompatible principal key type.");
	    krb5_free_keyblock_contents(kdc_context, out5);
	    out5->contents = NULL;
	    retval = -1;
	} else {
	    /* KLUDGE! If it's a non-raw des3 key, bash its enctype */
	    if (out5->enctype == ENCTYPE_DES3_CBC_SHA1 )
		out5->enctype = ENCTYPE_DES3_CBC_RAW;
	}
    }
    return(retval);
}

/* array of name-components + NULL ptr
 */

/*
 * Previously this code returned either a v4 key or a v5 key  and you
 * could tell from the enctype of the v5 key whether the v4 key was
 * useful.  Now we return both keys so the code can try both des3 and
 * des decryption.  We fail if the ticket doesn't have a v4 key.
 * Also, note as a side effect, the v5 key is basically useless  in
 * the client case.  It is still returned so the caller can free it.
 */
static int
kerb_get_principal(char *name, char *inst, /* could have wild cards */
		   Principal *principal,
		   int *more,	/* more tuples than room for */
		   krb5_keyblock *k5key, krb5_kvno kvno,
		   int issrv,	/* true if retrieving a service key */
		   krb5_deltat *k5life)
{
    /* Note that this structure should not be passed to the
       krb5_free* functions, because the pointers within it point
       to data with other references.  */
    krb5_principal search;

    krb5_db_entry entries;	/* filled in by krb5_db_get_principal() */
    int nprinc;			/* how many found */
    krb5_boolean more5;		/* are there more? */
    C_Block k;
    short toggle = 0;
    unsigned long *date;
    char* text;
    struct tm *tp;
    krb5_key_data *pkey;
    krb5_error_code retval;

    *more = 0;
    /* begin setting up the principal structure
     * with the first info we have:
     */
    memcpy( principal->name,     name, 1 + strlen( name));
    memcpy( principal->instance, inst, 1 + strlen( inst));

    /* the principal-name format changed between v4 & v5:
     *     v4: name.instance@realm
     *     v5: realm/name/instance
     *     in v5, null instance means the null-component doesn't exist.
     */

    if ((retval = krb5_425_conv_principal(kdc_context, name, inst, 
					  local_realm, &search)))
	return(0);

    /* The krb4 support in the KDC is not thread-safe yet, so maintain
       the global lock until that gets fixed.  */
    if ((retval = get_principal_locked(kdc_context, search, &entries, 
				       &nprinc, &more5))) {
        krb5_free_principal(kdc_context, search);
        return(0);
    }
    principal->key_low = principal->key_high = 0;
    krb5_free_principal(kdc_context, search);

    if (nprinc < 1) {
        *more = (int)more5 || (nprinc > 1);
        return(nprinc);
    } 

    if (!issrv) {
	if (krb5_dbe_find_enctype(kdc_context,
				  &entries,
				  ENCTYPE_DES_CBC_CRC,
				  KRB5_KDB_SALTTYPE_V4,
				  kvno,
				  &pkey) &&
	    krb5_dbe_find_enctype(kdc_context,
				  &entries,
				  ENCTYPE_DES_CBC_CRC,
				  -1,
				  kvno,
				  &pkey)) {
	    lt = klog(L_KRB_PERR,
		      "KDC V4: principal %s.%s isn't V4 compatible",
		      name, inst);
	    krb5_db_free_principal(kdc_context, &entries, nprinc);
	    return(0);
	}
    } else {
	if ( krb5_dbe_find_enctype(kdc_context, &entries,
				  ENCTYPE_DES_CBC_CRC,
				  KRB5_KDB_SALTTYPE_V4, kvno, &pkey) &&
	    krb5_dbe_find_enctype(kdc_context, &entries,
				  ENCTYPE_DES_CBC_CRC,
				  -1, kvno, &pkey)) {
	    lt = klog(L_KRB_PERR,
		      "KDC V4: failed to find key for %s.%s #%d",
		      name, inst, kvno);
	    krb5_db_free_principal(kdc_context, &entries, nprinc);
	    return(0);
	}
    }

    if (!compat_decrypt_key(pkey, k, k5key, issrv)) {
 	memcpy( &principal->key_low, k, LONGLEN);
       	memcpy( &principal->key_high, (krb5_ui_4 *) k + 1, LONGLEN);
    }
    memset(k, 0, sizeof k);
    if (issrv) {
	krb5_free_keyblock_contents (kdc_context, k5key);
      	if (krb5_dbe_find_enctype(kdc_context, &entries,
				  ENCTYPE_DES3_CBC_RAW,
				  -1, kvno, &pkey) &&
	    krb5_dbe_find_enctype(kdc_context, &entries,
				  ENCTYPE_DES3_CBC_SHA1,
				  -1, kvno, &pkey) &&
	    krb5_dbe_find_enctype(kdc_context, &entries,
				  ENCTYPE_DES_CBC_CRC,
				  KRB5_KDB_SALTTYPE_V4, kvno, &pkey) &&
	    krb5_dbe_find_enctype(kdc_context, &entries,
				  ENCTYPE_DES_CBC_CRC,
				  -1, kvno, &pkey)) {
	    lt = klog(L_KRB_PERR,
		      "KDC V4: failed to find key for %s.%s #%d (after having found it once)",
		      name, inst, kvno);
	    krb5_db_free_principal(kdc_context, &entries, nprinc);
	    return(0);
	}
	compat_decrypt_key(pkey, k, k5key, issrv);
	memset (k, 0, sizeof k);
    }


    /*
     * Convert v5's entries struct to v4's Principal struct:
     * v5's time-unit for lifetimes is 1 sec, while v4 uses 5 minutes,
     * and gets weirder above (128 * 300) seconds.
     */
    principal->max_life = krb_time_to_life(0, entries.max_life);
    if (k5life != NULL)
	*k5life = entries.max_life;
    /*
     * This is weird, but the intent is that the expiration is the minimum
     * of the principal expiration and key expiration
     */
    principal->exp_date = (unsigned long) 
        entries.expiration && entries.pw_expiration ?
        min(entries.expiration, entries.pw_expiration) :
        (entries.pw_expiration ? entries.pw_expiration :
        entries.expiration);
/*    principal->mod_date = (unsigned long) entries.mod_date; */
/* Set the master key version to 1. It's not really useful because all keys
 * will be encrypted in the same master key version, and digging out the 
 * actual key version will be harder than it's worth --proven */
/*    principal->kdc_key_ver = entries.mkvno; */
    principal->kdc_key_ver = 1;
    principal->key_version = pkey->key_data_kvno;
    /* We overload the attributes with the relevant v5 ones */
    principal->attributes = 0;
    if (isflagset(entries.attributes,  KRB5_KDB_REQUIRES_HW_AUTH) ||
	isflagset(entries.attributes,  KRB5_KDB_REQUIRES_PRE_AUTH)) {
          principal->attributes |= V4_KDB_REQUIRES_PREAUTH;
    }
    if (isflagset(entries.attributes,  KRB5_KDB_DISALLOW_ALL_TIX)) {
          principal->attributes |= V4_KDB_DISALLOW_ALL_TIX;
    }
    if (issrv && isflagset(entries.attributes, KRB5_KDB_DISALLOW_SVR)) {
	principal->attributes |= V4_KDB_DISALLOW_SVR;
    }
    if (isflagset(entries.attributes,  KRB5_KDB_REQUIRES_PWCHANGE)) {
          principal->attributes |= V4_KDB_REQUIRES_PWCHANGE;
    }

    /* set up v4 format of each date's text: */
    for ( date = &principal->exp_date, text = principal->exp_date_txt;
	  toggle ^= 1;
	  date = &principal->mod_date, text = principal->mod_date_txt) {
	tp = localtime( (time_t *) date);
	snprintf(text, sizeof(principal->mod_date_txt), "%4d-%02d-%02d",
		 tp->tm_year > 1900 ? tp->tm_year : tp->tm_year + 1900,
		 tp->tm_mon + 1, tp->tm_mday); /* January is 0, not 1 */
    }
    /*
     * free the storage held by the v5 entry struct,
     * which was allocated by krb5_db_get_principal().
     * this routine clears the keyblock's contents for us.
     */
    krb5_db_free_principal(kdc_context, &entries, nprinc);
    *more = (int) more5 || (nprinc > 1);
    return( nprinc);
}

static void str_length_check(char *str, int max_size)
{
	int	i;
	char	*cp;

	for (i=0, cp = str; i < max_size-1; i++, cp++) {
		if (*cp == 0)
			return;
	}
	*cp = 0;
}

static krb5_data *
kerberos_v4(struct sockaddr_in *client, KTEXT pkt)
{
    static KTEXT_ST rpkt_st;
    KTEXT   rpkt = &rpkt_st;
    static KTEXT_ST ciph_st;
    KTEXT   ciph = &ciph_st;
    static KTEXT_ST tk_st;
    KTEXT   tk = &tk_st;
    static KTEXT_ST auth_st;
    KTEXT   auth = &auth_st;
    AUTH_DAT ad_st;
    AUTH_DAT *ad = &ad_st;
    krb5_data *response = 0;

    static struct in_addr client_host;
    static int msg_byte_order;
    static int swap_bytes;
    static u_char k_flags;
 /* char   *p_name, *instance; */
    int     lifetime = 0;
    int     i;
    C_Block key;
    Key_schedule key_s;
    char   *ptr;

    krb5_keyblock k5key;
    krb5_kvno kvno;
    krb5_deltat sk5life, ck5life;
    KRB4_32 v4endtime, v4req_end;

    k5key.contents = NULL;	/* in case we have to free it */

    ciph->length = 0;

    client_host = client->sin_addr;

    /* eval macros and correct the byte order and alignment as needed */
    req_version = pkt_version(pkt);	/* 1 byte, version */
    req_msg_type = pkt_msg_type(pkt);	/* 1 byte, Kerberos msg type */

    /* set these to point to something safe */
    req_name_ptr = req_inst_ptr = req_realm_ptr = "";

    /* check if disabled, but we tell client */
    if (kdc_v4 == KDC_V4_DISABLE) {
	lt = klog(L_KRB_PERR,
	"KRB will not handle v4 request from %s",
		  inet_ntoa(client_host));
	/* send an error reply */
	req_name_ptr = req_inst_ptr = req_realm_ptr = "";
	return kerb_err_reply(client, pkt, KERB_ERR_PKT_VER, lt);
    }

    /* check packet version */
    if (req_version != KRB_PROT_VERSION) {
	lt = klog(L_KRB_PERR,
		  "KRB prot version mismatch: KRB =%d request = %d",
		  KRB_PROT_VERSION, req_version);
	/* send an error reply */
	req_name_ptr = req_inst_ptr = req_realm_ptr = "";
	return kerb_err_reply(client, pkt, KERB_ERR_PKT_VER, lt);
    }
    msg_byte_order = req_msg_type & 1;

    swap_bytes = 0;
    if (msg_byte_order != HOST_BYTE_ORDER) {
	swap_bytes++;
    }
    klog(L_KRB_PINFO,
	"Prot version: %d, Byte order: %d, Message type: %d",
	 (int) req_version, msg_byte_order, req_msg_type);

    switch (req_msg_type & ~1) {

    case AUTH_MSG_KDC_REQUEST:
	{
	    int    req_life;	/* Requested liftime */
	    unsigned int request_backdate =  0; /*How far to backdate
						  in seconds.*/
	    char   *service;	/* Service name */
	    char   *instance;	/* Service instance */
#ifdef notdef
	    int     kerno;	/* Kerberos error number */
#endif
	    n_auth_req++;
	    tk->length = 0;
	    k_flags = 0;	/* various kerberos flags */


	    /* set up and correct for byte order and alignment */
	    req_name_ptr = (char *) pkt_a_name(pkt);
	    str_length_check(req_name_ptr, ANAME_SZ);
	    req_inst_ptr = (char *) pkt_a_inst(pkt);
	    str_length_check(req_inst_ptr, INST_SZ);
	    req_realm_ptr = (char *) pkt_a_realm(pkt);
	    str_length_check(req_realm_ptr, REALM_SZ);
	    memcpy(&req_time_ws, pkt_time_ws(pkt), sizeof(req_time_ws));
	    /* time has to be diddled */
	    if (swap_bytes) {
		swap_u_long(req_time_ws);
	    }
	    ptr = (char *) pkt_time_ws(pkt) + 4;

	    req_life = (*ptr++) & 0xff;

	    service = ptr;
	    str_length_check(service, SNAME_SZ);
	    instance = ptr + strlen(service) + 1;
	    str_length_check(instance, INST_SZ);

	    rpkt = &rpkt_st;

	    klog(L_INI_REQ,
		 "Initial ticket request Host: %s User: \"%s\" \"%s\"",
		 inet_ntoa(client_host), req_name_ptr, req_inst_ptr);

	    if ((i = check_princ(req_name_ptr, req_inst_ptr, 0,
				 &a_name_data, &k5key, 0, &ck5life))) {
		response = kerb_err_reply(client, pkt, i, "check_princ failed");
		a_name_data.key_low = a_name_data.key_high = 0;
		krb5_free_keyblock_contents(kdc_context, &k5key);
		return response;
	    }
	    /* don't use k5key for client */
	    krb5_free_keyblock_contents(kdc_context, &k5key);
	    tk->length = 0;	/* init */
	    if (strcmp(service, "krbtgt"))
		klog(L_NTGT_INTK,
		     "INITIAL request from %s.%s for %s.%s", req_name_ptr,
		     req_inst_ptr, service, instance);
	    /* this does all the checking */
	    if ((i = check_princ(service, instance, lifetime,
				 &s_name_data, &k5key, 1, &sk5life))) {
		response = kerb_err_reply(client, pkt, i, "check_princ failed");
		a_name_data.key_high = a_name_data.key_low = 0;
		s_name_data.key_high = s_name_data.key_low = 0;
		krb5_free_keyblock_contents(kdc_context, &k5key);
		return response;
	    }
	    /* Bound requested lifetime with service and user */
	    v4req_end = krb_life_to_time(kerb_time.tv_sec, req_life);
	    v4req_end = min(v4req_end, kerb_time.tv_sec + ck5life);
	    v4req_end = min(v4req_end, kerb_time.tv_sec + sk5life);
	    lifetime = krb_time_to_life(kerb_time.tv_sec, v4req_end);
	    v4endtime = krb_life_to_time(kerb_time.tv_sec, lifetime);
	    /*
	     * Adjust issue time backwards if necessary, due to
	     * roundup in krb_time_to_life().
	     */
	    if (v4endtime > v4req_end)
		request_backdate = v4endtime - v4req_end;

#ifdef NOENCRYPTION
	    memset(session_key, 0, sizeof(C_Block));
#else
	    /* random session key */
	    des_new_random_key(session_key);
#endif

	    /* unseal server's key from master key */
	    memcpy( key,                &s_name_data.key_low,  4);
	    memcpy( ((krb5_ui_4 *) key) + 1, &s_name_data.key_high, 4);

	    s_name_data.key_low = s_name_data.key_high = 0;
	    kdb_encrypt_key(key, key, master_key,
			    master_key_schedule, DECRYPT);
	    /* construct and seal the ticket */
	    /* We always issue des tickets; the 3des tickets are a broken hack*/
	    krb_create_ticket(tk, k_flags, a_name_data.name,
			      a_name_data.instance, local_realm,
			      client_host.s_addr, (char *) session_key,
			      lifetime, kerb_time.tv_sec - request_backdate,
			      s_name_data.name, s_name_data.instance,
			      key);

	    krb5_free_keyblock_contents(kdc_context, &k5key);
	    memset(key, 0, sizeof(key));
	    memset(key_s, 0, sizeof(key_s));

	    /*
	     * get the user's key, unseal it from the server's key, and
	     * use it to seal the cipher 
	     */

	    /* a_name_data.key_low a_name_data.key_high */
	    memcpy( key,                &a_name_data.key_low,  4);
	    memcpy( ((krb5_ui_4 *) key) + 1, &a_name_data.key_high, 4);
	    a_name_data.key_low= a_name_data.key_high = 0;

	    /* unseal the a_name key from the master key */
	    kdb_encrypt_key(key, key, master_key, 
			    master_key_schedule, DECRYPT);

	    create_ciph(ciph, session_key, s_name_data.name,
			s_name_data.instance, local_realm, lifetime,
		  s_name_data.key_version, tk, kerb_time.tv_sec, key);

	    /* clear session key */
	    memset(session_key, 0, sizeof(session_key));

	    memset(key, 0, sizeof(key));



	    /* always send a reply packet */
	    rpkt = create_auth_reply(req_name_ptr, req_inst_ptr,
		req_realm_ptr, req_time_ws, 0, a_name_data.exp_date,
		a_name_data.key_version, ciph);
	    response = make_response((char *) rpkt->dat, rpkt->length);
	    memset(&a_name_data, 0, sizeof(a_name_data));
	    memset(&s_name_data, 0, sizeof(s_name_data));
	    break;
	}
    case AUTH_MSG_APPL_REQUEST:
	{
	    krb5_ui_4  time_ws;	/* Workstation time */
	    int    req_life;	/* Requested liftime */
	    char   *service;	/* Service name */
	    char   *instance;	/* Service instance */
	    int     kerno = 0;	/* Kerberos error number */
	    unsigned int request_backdate =  0; /*How far to backdate
						  in seconds.*/
	    char    tktrlm[REALM_SZ];

	    n_appl_req++;
	    tk->length = 0;
	    k_flags = 0;	/* various kerberos flags */

	    auth->mbz = 0;	/* pkt->mbz already zeroed */
	    auth->length = 4 + strlen((char *)pkt->dat + 3);
	    if (auth->length + 1 >= MAX_KTXT_LEN) {
		lt = klog(L_KRB_PERR,
			  "APPL request with realm length too long from %s",
			  inet_ntoa(client_host));
		return kerb_err_reply(client, pkt, RD_AP_INCON,
				      "realm length too long");
	    }

	    auth->length += (int) *(pkt->dat + auth->length) +
		(int) *(pkt->dat + auth->length + 1) + 2;
	    if (auth->length > MAX_KTXT_LEN) {
		lt = klog(L_KRB_PERR,
			  "APPL request with funky tkt or req_id length from %s",
			  inet_ntoa(client_host));
		return kerb_err_reply(client, pkt, RD_AP_INCON,
				      "funky tkt or req_id length");
	    }

	    memcpy(auth->dat, pkt->dat, auth->length);

	    strncpy(tktrlm, (char *)auth->dat + 3, REALM_SZ);
	    tktrlm[REALM_SZ-1] = '\0';
	    kvno = (krb5_kvno)auth->dat[2];
	    if ((!allow_v4_crossrealm)&&strcmp(tktrlm, local_realm) != 0) {
		lt = klog(L_ERR_UNK,
			  "Cross realm ticket from %s denied by policy,", tktrlm);
		return kerb_err_reply(client, pkt,
				      KERB_ERR_PRINCIPAL_UNKNOWN, lt);
	    }
	    if (set_tgtkey(tktrlm, kvno, 0)) {
		lt = klog(L_ERR_UNK,
			  "FAILED set_tgtkey realm %s, kvno %d. Host: %s ",
			  tktrlm, kvno, inet_ntoa(client_host));
		/* no better error code */
		return kerb_err_reply(client, pkt,
				      KERB_ERR_PRINCIPAL_UNKNOWN, lt);
	    }
	    kerno = krb_rd_req(auth, "krbtgt", tktrlm, client_host.s_addr,
			       ad, 0);
	    if (kerno) {
		if (set_tgtkey(tktrlm, kvno, 1)) {
		    lt = klog(L_ERR_UNK,
			      "FAILED 3des set_tgtkey realm %s, kvno %d. Host: %s ",
			      tktrlm, kvno, inet_ntoa(client_host));
		    /* no better error code */
		    return kerb_err_reply(client, pkt,
					  KERB_ERR_PRINCIPAL_UNKNOWN, lt);
		}
		kerno = krb_rd_req(auth, "krbtgt", tktrlm, client_host.s_addr,
				   ad, 0);
	    }

	    if (kerno) {
		klog(L_ERR_UNK, "FAILED krb_rd_req from %s: %s",
		     inet_ntoa(client_host), krb_get_err_text(kerno));
		req_name_ptr = req_inst_ptr = req_realm_ptr = "";
		return kerb_err_reply(client, pkt, kerno, "krb_rd_req failed");
	    }
	    ptr = (char *) pkt->dat + auth->length;

	    memcpy(&time_ws, ptr, 4);
	    ptr += 4;

	    req_life = (*ptr++) & 0xff;

	    service = ptr;
	    str_length_check(service, SNAME_SZ);
	    instance = ptr + strlen(service) + 1;
	    str_length_check(instance, INST_SZ);

	    klog(L_APPL_REQ, "APPL Request %s.%s@%s on %s for %s.%s",
		 ad->pname, ad->pinst, ad->prealm,
		 inet_ntoa(client_host), service, instance);
	    req_name_ptr = ad->pname;
	    req_inst_ptr = ad->pinst;
	    req_realm_ptr = ad->prealm;

	    if (strcmp(ad->prealm, tktrlm)) {
		return kerb_err_reply(client, pkt, KERB_ERR_PRINCIPAL_UNKNOWN,
				      "Can't hop realms");
	    }
	    if (!strcmp(service, "changepw")) {
		return kerb_err_reply(client, pkt, KERB_ERR_PRINCIPAL_UNKNOWN,
			      "Can't authorize password changed based on TGT");
	    }
	    kerno = check_princ(service, instance, req_life,
				&s_name_data, &k5key, 1, &sk5life);
	    if (kerno) {
		response = kerb_err_reply(client, pkt, kerno,
					  "check_princ failed");
		s_name_data.key_high = s_name_data.key_low = 0;
		krb5_free_keyblock_contents(kdc_context, &k5key);
		return response;
	    }
	    /* Bound requested lifetime with service and user */
	    v4endtime = krb_life_to_time((KRB4_32)ad->time_sec, ad->life);
	    v4req_end = krb_life_to_time(kerb_time.tv_sec, req_life);
	    v4req_end = min(v4endtime, v4req_end);
	    v4req_end = min(v4req_end, kerb_time.tv_sec + sk5life);

	    lifetime = krb_time_to_life(kerb_time.tv_sec, v4req_end);
	    v4endtime = krb_life_to_time(kerb_time.tv_sec, lifetime);
	    /*
	     * Adjust issue time backwards if necessary, due to
	     * roundup in krb_time_to_life().
	     */
	    if (v4endtime > v4req_end)
		request_backdate = v4endtime - v4req_end;

	    /* unseal server's key from master key */
	    memcpy(key,                &s_name_data.key_low,  4);
	    memcpy(((krb5_ui_4 *) key) + 1, &s_name_data.key_high, 4);
	    s_name_data.key_low = s_name_data.key_high = 0;
	    kdb_encrypt_key(key, key, master_key,
			    master_key_schedule, DECRYPT);
	    /* construct and seal the ticket */

#ifdef NOENCRYPTION
	    memset(session_key, 0, sizeof(C_Block));
#else
	    /* random session key */
	    des_new_random_key(session_key);
#endif

	    /* ALways issue des tickets*/
	    krb_create_ticket(tk, k_flags, ad->pname, ad->pinst,
			      ad->prealm, client_host.s_addr,
			      (char *) session_key, lifetime,
			      kerb_time.tv_sec - request_backdate,
			      s_name_data.name, s_name_data.instance,
			      key);
	    krb5_free_keyblock_contents(kdc_context, &k5key);
	    memset(key, 0, sizeof(key));
	    memset(key_s, 0, sizeof(key_s));

	    create_ciph(ciph, session_key, service, instance,
			local_realm,
			lifetime, s_name_data.key_version, tk,
			kerb_time.tv_sec, ad->session);

	    /* clear session key */
	    memset(session_key, 0, sizeof(session_key));

	    memset(ad->session, 0, sizeof(ad->session));

	    rpkt = create_auth_reply(ad->pname, ad->pinst,
				     ad->prealm, time_ws,
				     0, 0, 0, ciph);
	    response = make_response((char *) rpkt->dat, rpkt->length);
	    memset(&s_name_data, 0, sizeof(s_name_data));
	    break;
	}


#ifdef notdef_DIE
    case AUTH_MSG_DIE:
	{
	    lt = klog(L_DEATH_REQ,
	        "Host: %s User: \"%s\" \"%s\" Kerberos killed",
	        inet_ntoa(client_host), req_name_ptr, req_inst_ptr, 0);
	    exit(0);
	}
#endif /* notdef_DIE */

    default:
	{
	    lt = klog(L_KRB_PERR,
		"Unknown message type: %d from %s port %u",
		req_msg_type, inet_ntoa(client_host),
		ntohs(client->sin_port));
	    break;
	}
    }
    return response;
}



/*
 * kerb_er_reply creates an error reply packet and sends it to the
 * client. 
 */

static krb5_data *
kerb_err_reply(struct sockaddr_in *client, KTEXT pkt, long int err, char *string)
{
    static KTEXT_ST e_pkt_st;
    KTEXT   e_pkt = &e_pkt_st;
    static char e_msg[128];

    snprintf(e_msg, sizeof(e_msg), "\nKerberos error -- %s", string);
    cr_err_reply(e_pkt, req_name_ptr, req_inst_ptr, req_realm_ptr,
		 req_time_ws, err, e_msg);
    return make_response((char *) e_pkt->dat, e_pkt->length);
}

static int
check_princ(char *p_name, char *instance, int lifetime, Principal *p,
	    krb5_keyblock *k5key, int issrv, krb5_deltat *k5life)
{
    static int n;
    static int more;
 /* long trans; */

    n = kerb_get_principal(p_name, instance, p, &more, k5key, 0,
			   issrv, k5life);
    klog(L_ALL_REQ,
	 "Principal: \"%s\", Instance: \"%s\" Lifetime = %d n = %d",
	 p_name, instance, lifetime, n);
    
    if (n < 0) {
	lt = klog(L_KRB_PERR, "Database unavailable!");
	p->key_high = p->key_low = 0;    
	hang();
    }
    
    /*
     * if more than one p_name, pick one, randomly create a session key,
     * compute maximum lifetime, lookup authorizations if applicable,
     * and stuff into cipher. 
     */
    if (n == 0) {
	/* service unknown, log error, skip to next request */
	lt = klog(L_ERR_UNK, "UNKNOWN \"%s\" \"%s\"", p_name, instance);
	return KERB_ERR_PRINCIPAL_UNKNOWN;
    }
    if (more) {
	/* not unique, log error */
	lt = klog(L_ERR_NUN, "Principal NOT UNIQUE \"%s\" \"%s\"",
		  p_name, instance);
	return KERB_ERR_PRINCIPAL_NOT_UNIQUE;
    }

    /*
     * Check our V5 stuff first.
     */

    /*
     * Does the principal have REQUIRES_PWCHANGE set?
     */
    if (isflagset(p->attributes, V4_KDB_REQUIRES_PWCHANGE)) {
	lt = klog(L_ERR_SEXP, "V5 REQUIRES_PWCHANGE set "
		  "\"%s\" \"%s\"", p_name, instance);
	return KERB_ERR_NAME_EXP;
    }

    /*
     * Does the principal have DISALLOW_ALL_TIX set?
     */
    if (isflagset(p->attributes, V4_KDB_DISALLOW_ALL_TIX)) {
	lt = klog(L_ERR_SEXP, "V5 DISALLOW_ALL_TIX set: "
		  "\"%s\" \"%s\"", p_name, instance);
	/* Not sure of a better error to return */
	return KERB_ERR_NAME_EXP;
    }

    if (isflagset(p->attributes, V4_KDB_DISALLOW_SVR)) {
	lt = klog(L_ERR_SEXP, "V5 DISALLOW_SVR set: "
		  "\"%s\" \"%s\"", p_name, instance);
	/* Not sure of a better error to return */
	return KERB_ERR_NAME_EXP;
    }

    /*
     * Does the principal require preauthentication?
     */
    if ((kdc_v4 == KDC_V4_NOPREAUTH) &&
	isflagset(p->attributes, V4_KDB_REQUIRES_PREAUTH)) {
        lt = klog(L_ERR_SEXP, "V5 REQUIRES_PREAUTH set: "
		  "\"%s\" \"%s\"", p_name, instance);
	/* Not sure of a better error to return */
	return KERB_ERR_AUTH_EXP;
/*	return KERB_ERR_NAME_EXP;*/
    }

    /* If the user's key is null, we want to return an error */
    if (k5key->contents != NULL && K4KDC_ENCTYPE_OK(k5key->enctype)) {
	if ((p->key_low == 0) && (p->key_high == 0)) {
	    /* User has a null key */
	    lt = klog(L_ERR_NKY, "Null key \"%s\" \"%s\"", p_name, instance);
	    return KERB_ERR_NULL_KEY;
	}
    }
    /* make sure the service hasn't expired */
    if (((u_long) p->exp_date != 0)&&
	((u_long) p->exp_date <(u_long) kerb_time.tv_sec)) {
	/* service did expire, log it */
	char timestr[40];
	struct tm *tm;
	time_t t = p->exp_date;

	tm = localtime(&t);
	if (!strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tm))
	    timestr[0] = '\0';
	lt = klog(L_ERR_SEXP,
		  "EXPIRED \"%s\" \"%s\"  %s", p->name, p->instance, timestr);
	return KERB_ERR_NAME_EXP;
    }
    /* ok is zero */
    return 0;
}


/* Set the key for krb_rd_req so we can check tgt */
static int
set_tgtkey(char *r, krb5_kvno kvno, krb5_boolean use_3des)
{
    int     n;
    static char lastrealm[REALM_SZ] = "";
    static int last_kvno = 0;
    static krb5_boolean last_use_3des = 0;
    static int more;
    Principal p_st;
    Principal *p = &p_st;
    C_Block key;
    krb5_keyblock k5key;

    k5key.contents = NULL;
    if (!strcmp(lastrealm, r) && last_kvno == kvno && last_use_3des == use_3des)
	return (KSUCCESS);

/*  log("Getting key for %s", r); */

    n = kerb_get_principal("krbtgt", r, p, &more, &k5key, kvno, 1, NULL);
    if (n == 0)
	return (KFAILURE);

    if (isflagset(p->attributes, V4_KDB_DISALLOW_ALL_TIX)) {
	lt = klog(L_ERR_SEXP,
		  "V5 DISALLOW_ALL_TIX set: \"krbtgt\" \"%s\"", r);
	krb5_free_keyblock_contents(kdc_context, &k5key);
	return KFAILURE;
    }

    if (isflagset(p->attributes, V4_KDB_DISALLOW_SVR)) {
	lt = klog(L_ERR_SEXP, "V5 DISALLOW_SVR set: \"krbtgt\" \"%s\"", r);
	krb5_free_keyblock_contents(kdc_context, &k5key);
	return KFAILURE;
    }

    if (use_3des&&!K4KDC_ENCTYPE_OK(k5key.enctype)) {
	krb_set_key_krb5(kdc_context, &k5key);
	strncpy(lastrealm, r, sizeof(lastrealm) - 1);
	lastrealm[sizeof(lastrealm) - 1] = '\0';
	last_kvno = kvno;
	last_use_3des = use_3des;
    } else {
	/* unseal tgt key from master key */
	memcpy(key,                &p->key_low,  4);
	memcpy(((krb5_ui_4 *) key) + 1, &p->key_high, 4);
	kdb_encrypt_key(key, key, master_key,
			master_key_schedule, DECRYPT);
	krb_set_key((char *) key, 0);
	strncpy(lastrealm, r, sizeof(lastrealm) - 1);
	lastrealm[sizeof(lastrealm) - 1] = '\0';
	last_kvno = kvno;
    }
    krb5_free_keyblock_contents(kdc_context, &k5key);
    return (KSUCCESS);
}

#else	/* KRB5_KRB4_COMPAT */
#include "k5-int.h"
#endif /* KRB5_KRB4_COMPAT */
