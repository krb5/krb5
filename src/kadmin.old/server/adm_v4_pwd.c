
/* 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include <stdio.h>

#define         MAX_KTXT_LEN    1250
#define 	ANAME_SZ	40
#define		INST_SZ		40
#define		REALM_SZ	40
#define		DATE_SZ         26

typedef unsigned char des_cblock[8];	/* crypto-block size */
#define C_Block des_cblock
typedef struct des_ks_struct { des_cblock _; } des_key_schedule[16];
#define Key_schedule des_key_schedule

int des_debug = 0;

struct ktext {
    int     length;             /* Length of the text */
    unsigned char dat[MAX_KTXT_LEN];    /* The data itself */
    unsigned long mbz;          /* zero to catch runaway strings */
};

typedef struct ktext *KTEXT;
typedef struct ktext KTEXT_ST;

struct auth_dat {
    unsigned char k_flags;      /* Flags from ticket */
    char    pname[ANAME_SZ];    /* Principal's name */
    char    pinst[INST_SZ];     /* His Instance */
    char    prealm[REALM_SZ];   /* His Realm */
    unsigned long checksum;     /* Data checksum (opt) */
    C_Block session;            /* Session Key */
    int     life;               /* Life of ticket */
    unsigned long time_sec;     /* Time ticket issued */
    unsigned long address;      /* Address in ticket */
    KTEXT_ST reply;             /* Auth reply (opt) */
};

typedef struct auth_dat AUTH_DAT;

#define KADM_VERSTR	"SKADM.m1"
#define KADM_VERSIZE strlen(KADM_VERSTR)

struct msg_dat {
    unsigned char *app_data;    /* pointer to appl data */
    unsigned long app_length;   /* length of appl data */
    unsigned long hash;         /* hash to lookup replay */
    int     swap;               /* swap bytes? */
    long    time_sec;           /* msg timestamp seconds */
    unsigned char time_5ms;     /* msg timestamp 5ms units */
};

typedef struct msg_dat MSG_DAT;

typedef struct {
    char    name[ANAME_SZ];
    char    instance[INST_SZ];
 
    unsigned long key_low;
    unsigned long key_high;
    unsigned long exp_date;
    char    exp_date_txt[DATE_SZ];
    unsigned long mod_date;
    char    mod_date_txt[DATE_SZ];
    unsigned short attributes;
    unsigned char max_life;
    unsigned char kdc_key_ver;
    unsigned char key_version;
 
    char mod_name[ANAME_SZ];
    char mod_instance[INST_SZ];
    char *old;
} V4_Principal;

        /* V5 Definitions */
#include "k5-int.h"
#include "adm_extern.h"

struct saltblock {
    int salttype;
    krb5_data saltdata;
};

struct cpw_keyproc_arg {
    krb5_keyblock *key;
};

/*
process_v4_kpasswd
unwrap the data stored in dat, process, and return it.
 */
process_v4_kpasswd(dat, dat_len, cpw_key)
u_char **dat;
int *dat_len;
struct cpw_keyproc_arg *cpw_key;

{
    u_char *in_st;                      /* pointer into the sent packet */
    int in_len,retc;                    /* where in packet we are, for
                                           returns */
    u_long r_len;                       /* length of the actual packet */
    KTEXT_ST authent;                   /* the authenticator */
    AUTH_DAT ad;                        /* who is this, klink */
    u_long ncksum;                      /* checksum of encrypted data */
    des_key_schedule sess_sched;        /* our schedule */
    MSG_DAT msg_st;
    u_char *retdat, *tmpdat;
    int retval, retlen;
    u_short dlen;
    extern int errno;

    if (strncmp(KADM_VERSTR, (char *) *dat, KADM_VERSIZE)) {
	syslog(LOG_ERR, "process_v4_kpasswd: Bad Version String");
        return(1);
    }

    in_len = KADM_VERSIZE;
    			/* get the length */
    if ((retc = stv_long(*dat, &r_len, in_len, *dat_len)) < 0) {
	syslog(LOG_AUTH | LOG_INFO, "process_v4_kpasswd: Bad Length");
        return(1);
    }

    in_len += retc;
    authent.length = *dat_len - r_len - KADM_VERSIZE - sizeof(u_long);
    memcpy((char *) authent.dat, (char *) (*dat) + in_len, authent.length);
    authent.mbz = 0;

    if (retval = krb_set_key(cpw_key->key->contents, 0) != 0) {
	syslog(LOG_ERR, "process_v4_kpasswd: Bad set_key Request");
        return(1);
    }

    /* service key should be set before here */
    if (retc = krb4_rd_req(&authent, 
			   CPWNAME, 
			   client_server_info.server->realm.data,
			   client_server_info.client_name.sin_addr.s_addr,
			   &ad, 
			   (char *) 0)) {
	syslog(LOG_AUTH | LOG_INFO, "process_v4_kpasswd: Bad Read Request");
        return(1);
    }

#define clr_cli_secrets() \
{ \
	memset((char *) sess_sched, 0, sizeof(sess_sched)); \
	memset((char *) ad.session, 0, sizeof(ad.session)); \
}
 
    in_st = *dat + *dat_len - r_len;
    ncksum = des_quad_cksum(in_st, (u_long *) 0, (long) r_len, 0, ad.session);
    if (ncksum!=ad.checksum) {          /* yow, are we correct yet */
        clr_cli_secrets();
	syslog(LOG_ERR, "process_v4_kpasswd: Invalid Checksum");
        return(1);
    }

    des_key_sched(ad.session, sess_sched);

    if (retc = (int) krb4_rd_priv(in_st, 
			    r_len, 
			    sess_sched, 
			    ad.session,
			    &client_server_info.client_name,
			    &client_server_info.server_name,
			    &msg_st)) {
	syslog(LOG_ERR, "process_v4_kpasswd: Bad Read Private Code = %d",
		retc);
        clr_cli_secrets();
        return(1);
    }

    if (msg_st.app_data[0] != 2) { /* Only Valid Request is CHANGE_PW = 2 */
	syslog(LOG_ERR, "process_v4_kpasswd: Invalid V4 Request");
        clr_cli_secrets();
        return(1);
    }

    retval = adm_v4_cpw(msg_st.app_data+1,
		    (int) msg_st.app_length,
		    &ad,
		    &retdat, 
		    &retlen);

    if (retval) {
	syslog(LOG_ERR, 
		"process_v4_kpasswd: Password Modification for %s%s%s Failed",
		ad.pname, (ad.pinst[0] != '\0') ? "/" : "",
		(ad.pinst[0] != '\0') ? ad.pinst : "");
    } else {
	syslog(LOG_ERR, 
		"process_v4_kpasswd: Password Modification for %s%s%s Complete",
		ad.pname, (ad.pinst[0] != '\0') ? "/" : "",
		(ad.pinst[0] != '\0') ? ad.pinst : "");
    }

    /* Now seal the response back into a priv msg */
    free((char *)*dat);
    tmpdat = (u_char *) malloc((unsigned)(retlen + KADM_VERSIZE +
                                          sizeof(u_long)));

    (void) strncpy((char *) tmpdat, KADM_VERSTR, KADM_VERSIZE);

    retval = htonl((u_long) retval);

    memcpy((char *) tmpdat + KADM_VERSIZE, (char *) &retval, sizeof(u_long));

    if (retlen) {
        memcpy((char *) tmpdat + KADM_VERSIZE + sizeof(u_long),
	       (char *) retdat, retlen);
        free((char *) retdat);
    }

    /* slop for mk_priv stuff */
    *dat = (u_char *) malloc((unsigned) (retlen + KADM_VERSIZE +
                                         sizeof(u_long) + 200));

    if ((*dat_len = krb4_mk_priv(tmpdat, *dat,
                                (u_long) (retlen + KADM_VERSIZE +
                                          sizeof(u_long)),
                                sess_sched,
                                ad.session, 
				&client_server_info.server_name,
                                &client_server_info.client_name)) < 0) {
        clr_cli_secrets();
	syslog(LOG_ERR, "process_v4_kpasswd: Bad mk_priv");
        return(1);
    }

    dlen = (u_short) *dat_len;

    dlen = htons(dlen);

    if (krb5_net_write(context, client_server_info.client_socket, 
			(char *) &dlen, 2) < 0) {
	syslog(LOG_ERR, "process_v4_kpasswd: Error writing dlen to client");
	(void) close(client_server_info.client_socket);
    }
    
    if (krb5_net_write(context, client_server_info.client_socket, 
			(char *) *dat, *dat_len) < 0) {
	syslog(LOG_ERR, "writing to client: %s",error_message(errno));
	(void) close(client_server_info.client_socket);
    }

    free((char *) *dat);
    clr_cli_secrets();
 
    return(0);
}

krb5_kvno
princ_exists(context, principal, entry)
    krb5_context context;
    krb5_principal principal;
    krb5_db_entry *entry;
{
    int nprincs = 1;
    krb5_boolean more;
    krb5_error_code retval;
    krb5_kvno vno;

    nprincs = 1;
    if (retval = krb5_db_get_principal(context, principal, entry, 
				       &nprincs, &more)) {
        return 0;
    }

    if (!nprincs)
            return 0;

    return(nprincs);
}

/*
adm_v4_cpw - the server side of the change_password routine
  recieves    : KTEXT, {key}
  returns     : CKSUM, RETCODE
  acl         : caller can change only own password

Replaces the password (i.e. des key) of the caller with that specified in key.
Returns no actual data from the master server, since this is called by a user
*/
int
adm_v4_cpw(dat, len, ad, datout, outlen)
u_char *dat;
int len;
AUTH_DAT *ad;
u_char **datout;
int *outlen;
{
    krb5_db_entry entry;
    krb5_keyblock *v5_keyblock;

    int number_of_principals;
    krb5_error_code retval;
    int one = 1;
    char v5_principal[255];

    C_Block  v4_clear_key;
    unsigned long keylow, keyhigh;
    int stvlen;
 
	/* Identify the Customer */
    (void) sprintf(v5_principal, "%s%s%s\0", ad->pname, 
		(ad->pinst[0] != '\0') ? "/" : "", 
		(ad->pinst[0] != '\0') ? ad->pinst : "");

    /* take key off the stream, and change the database */
 
    if ((stvlen = stv_long(dat, &keyhigh, 0, len)) < 0) {
	syslog(LOG_ERR, "adm_v4_cpw - (keyhigh) Length Error for stv_long");
        return(1);
    }
    if (stv_long(dat, &keylow, stvlen, len) < 0) {
	syslog(LOG_ERR, "adm_v4_cpw - (keylow) Length Error for stv_long");
        return(1);
    }
 
    keylow = ntohl(keylow);
    keyhigh = ntohl(keyhigh);

                        /* Convert V4 Key to V5 Key */
    (void) memcpy(v4_clear_key, (char *) &keylow, 4);
    (void) memcpy(((long *) v4_clear_key) + 1, (char *) &keyhigh, 4);

                        /* Zero Next Output Entry */
    memset((char *) &entry, 0, sizeof(entry));

    if (retval = krb5_parse_name(context, v5_principal, &entry.principal)) {
        syslog(LOG_ERR, "adm_v4_cpw - Error parsing %s",
                v5_principal);
        return(1);
    }

   if (!(number_of_principals = princ_exists(entry.principal, &entry))) {
        syslog(LOG_ERR, "adm_v4_cpw - principal %s is NOT in the database",
                v5_principal);
        return(1);
    }

                /* Allocate v5_keyblock and fill some fields */
    if (!(v5_keyblock = (krb5_keyblock *) calloc (1,
                sizeof(krb5_keyblock)))) {
        syslog(LOG_ERR, "adm_v4_cpw - Error Allocating krb5_keyblock");
        return(1);
    }  
 
    v5_keyblock->enctype = ENCTYPE_DES_CBC_MD5;
    v5_keyblock->length = 8;
    if (!(v5_keyblock->contents = (krb5_octet *) calloc (1,
                8))) {
        syslog(LOG_ERR, 
		"adm_v4_cpw - Error Allocating krb5_keyblock->contents\n");
        free(v5_keyblock);
        return(1);
    }
 
    memcpy(v5_keyblock->contents, v4_clear_key, 8);

    if (retval = krb5_kdb_encrypt_key(context, &master_encblock,
                                  v5_keyblock,
                                  &entry.key)) {
	syslog(LOG_ERR, 
		"adm_v4_cpw - Error %d while encrypting key for '%s'\n", retval,
                        v5_principal);
	return(1);
    }
    entry.alt_key.length = 0;

		/* Increment Version Number */
    entry.kvno = entry.kvno + 1;
#ifdef SANDIA
    entry.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;
#endif
    if (retval = krb5_timeofday(context, &entry.mod_date)) {
        syslog(LOG_ERR, "adm_v4_cpw - Error while fetching date");
        return(1);
    }
#ifdef SANDIA
    entry.last_pwd_change = entry.mod_date;
#endif
    entry.mod_name = entry.principal; /* Should be Person who did Action */

        /* Write the Modified Principal to the V5 Database */
    if (retval = krb5_db_put_principal(context, &entry, &one)) {
        syslog(LOG_ERR, 
		"adm_v4_cpw - Error %d while Entering Principal for '%s'", 
		retval, v5_principal);
        return(1);
    }

    *datout = 0;
    *outlen = 0;
 
    return(0);
}

stv_long(st, dat, loc, maxlen)
u_char *st;                     /* a base pointer to the stream */
u_long *dat;                    /* the attributes field */
int loc;                        /* offset into the stream for current data */
int maxlen;                     /* maximum length of st */
{
    u_long temp = 0;            /* to hold the net order short */

#if (SIZEOF_LONG == 4)
    if (loc + 4 > maxlen)
	return(-1);
    (void) memcpy((char *) &temp + 4, (char *) ((u_long)st + (u_long)loc), 4);
    *dat = ntohl(temp);         /* convert to network order */
    return(4);
#else
    if (loc + sizeof(u_long) > maxlen)
	return(-1);
    (void) memcpy((char *) &temp, (char *) ((u_long)st + (u_long)loc), 
		sizeof(u_long));
    *dat = ntohl(temp);         /* convert to network order */
    return(sizeof(u_long));
#endif
}
