#include "tnae.h"
#include <SetupA4.h>
/*
 * The intrinsic Authorization Module, usefull for debugging a module built in to the app
 * long AuthModule(long, char*);
 */


#ifdef KRB5
#	include "k5-int.h"
#	include "com_err.h"
#	include "prof_int.h"
#	include "krb5.h"
#endif
#define KRB_SERVICE_NAME    "host"
#define K5_REJECT				1
#define K5_ACCEPT				2
#define K5_RESPONSE				3           // They had to make it different
#define KSUCCESS    0
#define KFAILURE    255

static krb5_context k5_context;
static krb5_auth_context *auth_context;

long	main(long func, char *parameters);
static int 	k5_auth_send (int how, char *szHostName, char *szUserName, krb5_data *auth);
static int	k5_auth_reply (int how, unsigned char *data, int cnt);
static	void tn_sendsub (tnParams *tn, int code, int request, char *scp, int length);
static	void tn_sendauthsub (tnParams *tn, int code, int request, int vers, int how, int auth, char *scp, int length);

long
main(long func, char *parameters)
{
tnParams *tn;
char *so;
char *cp;
long					err;
long					oldA4;

	oldA4 = SetUpA4();
		
	switch (func) {
		case TNFUNC_INIT_CODE:
			/*
			 * Initialize this code module.
			 *
			 * parameters: points to area to save type/modifier pairs
			 * returns: the number of pairs entered.
			 */
			cp = (unsigned char *)parameters;
//			*cp++ = AUTH_KERBEROS_V5;
//			*cp++ = AUTH_HOW_MUTUAL;		/* also need AUTH_CLIENT_TO_SERVER ??? ddd */
			*cp++ = AUTH_KERBEROS_V5;
			*cp++ = AUTH_HOW_ONE_WAY;
			err = 2;						/* 2 pairs */

			/* initialize krb5 */
		    krb5_init_context(&k5_context);
		    krb5_init_ets(k5_context);
			break;
	
		case TNFUNC_INIT_SESSION_AUTH:
			/*
			 * Initialize auth session data.
			 *
			 * parameters: pointer to where to save pointer to auth data.
			 */
			*parameters = (long) NewPtr(10);
			
			break;

/* we don't do session encryption now */
		case TNFUNC_INIT_SESSION_ENCRYPT:
			err = 0;	/* we do NOT do option 38 encrypt */
			break;
		case TNFUNC_ENCRYPT_SB:
			err = 0;	/* we do NOT do option 38 encrypt */
			break;
	
		case TNFUNC_DECRYPT:
			err = 0;	/* we do NOT do option 38 encrypt */
			break;
	
		case TNFUNC_ENCRYPT:
			err = 0;	/* we do NOT do option 38 encrypt */
			break;

		case TNFUNC_QUERY_ENCRYPT:
			err = 0;	/* we do NOT do option 38 encrypt */
			break;	
	
		case TNFUNC_AUTH_SEND:
		{
		krb5_data	auth;
		char		szUserName[100] = "";
		char		server[100];
			/*
			 * Process [IAC SB] AUTH SEND <type-modifier-list> [IAC SE] sub-option.
			 *
			 * parameters: k4aeAuthMan *
			 */
			/* Use k5 to get the credentials to send in as response */
			tn = (tnParams *)parameters;
			so = &tn->subbuffer[SB_TYPE];
			strcpy(server, tn->cname);
			server[strlen(server) - 1] = 0;	// knock last character off "."
			if (k5_auth_send(so[1], server, szUserName, &auth))
			{
				tn_sendsub(tn, OPT_AUTHENTICATION, TNQ_NAME, szUserName, strlen(szUserName));
				tn_sendauthsub(tn, OPT_AUTHENTICATION, TNQ_IS, AUTH_KERBEROS_V5, so[1] | AUTH_CLIENT_TO_SERVER, KRB_AUTH, auth.data, auth.length);
			}
			else
				err = 1;
		}
		break;
	
		case TNFUNC_AUTH_REPLY:
			/*
			 * Process an [IAC SB] AUTH REPLY <type-modifier-list> [IAC SE] sub-option.
			 *
			 * parameters: k4aeAuthMan *
			 */
			tn = (tnParams *)parameters;
			so = &tn->subbuffer[SB_TYPE];
			k5_auth_reply(so[1], tn->subbuffer, tn->sublength);
			break;

		default:
			err = TNREP_ERROR;
	}

	RestoreA4(oldA4);
	return err;
}

/*
** 
** K5_auth_send - gets authentication bits we need to send to KDC.
** 
** Code lifted from wintel code in the windows directory.)
** (Code lifted from telnet sample code in the appl directory.)
**
** Result is left in auth
**
** Returns: 0 on failure, 1 on success
** 
*/

static int 
k5_auth_send (int how, char *szHostName, char *szUserName, krb5_data *auth)
{
	krb5_error_code r;
	krb5_ccache ccache;
    krb5_creds cred;
	krb5_creds * new_cred;
	krb5_flags ap_opts;
    int len;

	if (r = krb5_cc_default(k5_context, &ccache)) {
        com_err (NULL, r, "while authorizing.");
		return(0);
	}

	memset((char *)&cred, 0, sizeof(cred));
	if (r = krb5_sname_to_principal(k5_context, szHostName, KRB_SERVICE_NAME,
            KRB5_NT_SRV_HST, &cred.server)) {
        com_err (NULL, r, "while authorizing.");
        return(0);
    }

	if (r = krb5_cc_get_principal(k5_context, ccache, &cred.client)) {
        com_err (NULL, r, "while authorizing.");
        krb5_free_cred_contents(k5_context, &cred);
		return(0);
	}
    if (szUserName[0] == '\0') {                /* Get user name now */
        len  = krb5_princ_component(k5_context, cred.client, 0)->length;
        memcpy (szUserName,
            krb5_princ_component(k5_context, cred.client, 0)->data,
            len);
        szUserName[len] = '\0';
    }


	if (r = krb5_get_credentials(k5_context, 0,
				     ccache, &cred, &new_cred)) {
        com_err (NULL, r, "while authorizing.");
		krb5_free_cred_contents(k5_context, &cred);
		return(0);
	}

    ap_opts = 0;
	if ((how & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL)
	    ap_opts = AP_OPTS_MUTUAL_REQUIRED;

	r = krb5_mk_req_extended(k5_context, (void*) &auth_context, ap_opts,
				 NULL, new_cred, auth);

	krb5_free_cred_contents(k5_context, &cred);
	krb5_free_creds(k5_context, new_cred);

	if (r) {
        com_err (NULL, r, "while authorizing.");
		return(0);
	}

	return(1);
}

/*+
** 
** K5_auth_reply -- checks the reply for mutual authentication.
**
** Code lifted from telnet sample code in the appl directory.
** 
*/
static int
k5_auth_reply (int how, unsigned char *data, int cnt) {
    static int mutual_complete = 0;
	char strTmp[100];

    data += 4;                                  /* Point to status byte */

	switch (*data++) {
	case K5_REJECT:
        if (cnt > 0)
            sprintf (strTmp,
                "Kerberos V5 refuses authentication because %.*s",
                cnt, data);
		else
			sprintf (strTmp, "Kerberos V5 refuses authentication");
        com_err (NULL, 0, strTmp);

		return KFAILURE;

	case K5_ACCEPT:
		if ((how & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL && !mutual_complete) {
		    sprintf(strTmp, "Kerberos V5 accepted you, " 
              "but didn't provide mutual authentication");
        	com_err (NULL, 0, strTmp);
		    return KSUCCESS;
		}

        return KSUCCESS;
		break;

	case K5_RESPONSE:
		if ((how & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) {
		    /* the rest of the reply should contain a krb_ap_rep */
		    krb5_ap_rep_enc_part *reply;
		    krb5_data inbuf;
		    krb5_error_code r;

		    inbuf.length = cnt;
		    inbuf.data = (char *)data;

		    if (r = krb5_rd_rep (k5_context, (void*) auth_context, &inbuf, &reply)) {
                com_err (NULL, r, "while authorizing.");
                return KFAILURE;
		    }
		    krb5_free_ap_rep_enc_part(k5_context, reply);

		    mutual_complete = 1;
		}
		return KSUCCESS;

	default:
		return KSUCCESS;                        // Unknown reply type
	}
}


/*+
 * Function: Copy data to buffer, doubling IAC character if present.
 *
 * Parameters:
 *	kstream - kstream to send abort message to.
 */
static int
copy_for_net(
	unsigned char *to,
	unsigned char *from,
	int c)
{
	int n;

	n = c;

	while (c-- > 0) {
		if ((*to++ = *from++) == IAC) {
			n++;
			*to++ = IAC;
		}
	}

	return n;

} /* copy_for_net */


/*
 * Insert a suboption into the suboption buffer.
 */
static	void tn_sendsub (tnParams *tn, int code, int request, char *scp, int length)
{
	int len;
	unsigned char *src, *lp, *limit;
	char start[] = {IAC, SB, 0, 0};
	char end[] = {IAC, SE};
	unsigned char *dst = tn->sendbuffer;

	src = (unsigned char *)scp;
	limit = src + length;
	start[2] = code;
	start[3] = request;

	BlockMoveData(start, dst, sizeof(start));
	dst += sizeof(start);

	/*
	 * Encode the buffer. IACs must be doubled
	 */
	if (*src == IAC) {						/* check initial iac in buffer */
		*dst++ = IAC;
	}
	while (src < limit) {
		lp = src+1;							/* dont check first char */
		while (lp < limit) {				/* scan for IAC */
			if (*lp == IAC)
				break;
			lp++;		
		}
		len = lp - src;
		if (lp < limit)						/* if stopped on IAC */
			len++;							/* include IAC in xmit */

		BlockMoveData(src, dst, len);
		dst += len;

		src = lp;							/* resume scanning */
    }

	BlockMoveData(end, dst, 2);
	dst += 2;

	len = dst - tn->sendbuffer;
	*tn->sendlength -= len;
	tn->sendbuffer += len;
}


/*
 * Insert a suboption into the suboption buffer.
 */
static	void tn_sendauthsub (tnParams *tn, int code, int request, int vers, int how, int auth, char *scp, int length)
{
	int len;
	unsigned char *src, *lp, *limit;
	char start[] = {IAC, SB, 0, 0, 0, 0, 0};
	char end[] = {IAC, SE};
	unsigned char *dst = tn->sendbuffer;

	src = (unsigned char *)scp;
	limit = src + length;
	start[2] = code;
	start[3] = request;
	start[4] = vers;
	start[5] = how;
	start[6] = auth;

	BlockMoveData(start, dst, sizeof(start));
	dst += sizeof(start);

	/*
	 * Encode the buffer. IACs must be doubled
	 */
	if (*src == IAC) {						/* check initial iac in buffer */
		*dst++ = IAC;
	}
	while (src < limit) {
		lp = src+1;							/* dont check first char */
		while (lp < limit) {				/* scan for IAC */
			if (*lp == IAC)
				break;
			lp++;		
		}
		len = lp - src;
		if (lp < limit)						/* if stopped on IAC */
			len++;							/* include IAC in xmit */

		BlockMoveData(src, dst, len);
		dst += len;

		src = lp;							/* resume scanning */
    }

	BlockMoveData(end, dst, 2);
	dst += 2;

	len = dst - tn->sendbuffer;
	*tn->sendlength -= len;
	tn->sendbuffer += len;
}

extern void (*__exit_proc__)(void);
void (*__exit_proc__)(void);
