/*
 * Implements Kerberos 4 authentication
 */

#ifdef KRB4
	#include <windows.h>
	#include <time.h>
	#include <string.h>
	#include "winsock.h"
    #include "kerberos.h"
#endif
#ifdef KRB5
	#include <time.h>
	#include <string.h>
    #include "krb5.h"
    #include "com_err.h"
#endif

#include "telnet.h"
#include "telopts.h"

/*
 * Constants
 */
	#define IS						0
	#define SEND					1
	#define REPLY					2
	#define NAME					3

	#define AUTH_NULL				0
	#define KERBEROS_V4				1
	#define KERBEROS_V5				2
	#define SPX						3
	#define RSA            			6
	#define LOKI           		   10

	#define AUTH					0
	#define K4_REJECT				1
	#define K4_ACCEPT				2
	#define K4_CHALLENGE			3
	#define K4_RESPONSE				4

	#define K5_REJECT				1
	#define K5_ACCEPT				2
	#define K5_RESPONSE				3           // They had to make it different

	#define AUTH_WHO_MASK		    1
	#define AUTH_CLIENT_TO_SERVER   0
	#define AUTH_SERVER_TO_CLIENT   1

	#define AUTH_HOW_MASK		    2
	#define AUTH_HOW_ONE_WAY        0
	#define AUTH_HOW_MUTUAL         2

    #ifndef KSUCCESS                            // Let K5 use K4 constants
        #define KSUCCESS    0
        #define KFAILURE    255
    #endif
/*
 * Globals
 */
    #ifdef KRB4
    	static CREDENTIALS cred;
    	static KTEXT_ST auth;

    	#define KRB_SERVICE_NAME    "rcmd"
        #define KERBEROS_VERSION    KERBEROS_V4

    	static int auth_how;
        static int k4_auth_send  (kstream ks);
        static int k4_auth_reply (kstream ks, unsigned char *data, int cnt);
    #endif
    #ifdef KRB5
        static krb5_data auth;
    	static int auth_how;
        static krb5_auth_context auth_context;

        #define KRB_SERVICE_NAME    "host"
        #define KERBEROS_VERSION    KERBEROS_V5

        static int k5_auth_send  (int how);
        static int k5_auth_reply (int how, unsigned char *data, int cnt);
    #endif

	BOOL encrypt_enable;

/*+
 * Function: Enable or disable the encryption process.
 *
 * Parameters:
 *	enable - TRUE to enable, FALSE to disable.
 */
static void
auth_encrypt_enable(
	BOOL enable)
{
	encrypt_enable = enable;

} /* auth_encrypt_enable */


/*+
 * Function: Abort the authentication process
 *
 * Parameters:
 *	ks - kstream to send abort message to.
 */
static void
auth_abort(
	kstream ks,
	char *errmsg,
	long r)
{
    char buf[9];

	wsprintf(buf, "%c%c%c%c%c%c%c%c", IAC, SB, AUTHENTICATION, IS, AUTH_NULL,
        AUTH_NULL, IAC, SE);
	TelnetSend(ks, (LPSTR)buf, 8, 0);

	if (errmsg != NULL) {
		strcpy(strTmp, errmsg);

		if (r != KSUCCESS) {
			strcat(strTmp, "\n");
            #ifdef KRB4
                lstrcat(strTmp, krb_get_err_text((int) r));
            #endif
            #ifdef KRB5
                lstrcat (strTmp, error_message(r));
            #endif
		}

		MessageBox(HWND_DESKTOP, strTmp, "Kerberos authentication failed!",
            MB_OK | MB_ICONEXCLAMATION);
	}

} /* auth_abort */


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


/*++
 * Function: Parse authentication send command
 *
 * Parameters:
 *	ks - kstream to send abort message to.
 *
 *  parsedat - the sub-command data.
 *
 *	end_sub - index of the character in the 'parsedat' array which
 *		is the last byte in a sub-negotiation
 *
 * Returns: Kerberos error code.
 */
static int
auth_send(
	kstream ks,
	unsigned char *parsedat,
	int end_sub)
{
    char buf[512];
	char *pname;
    int plen;
	int r;
	int i;

	auth_how = -1;

	for (i = 2; i+1 <= end_sub; i += 2) {
		if (parsedat[i] == KERBEROS_VERSION)
			if ((parsedat[i+1] & AUTH_WHO_MASK) == AUTH_CLIENT_TO_SERVER) {
				auth_how = parsedat[i+1] & AUTH_HOW_MASK;
				break;
			}
	}

	if (auth_how == -1) {
		auth_abort(ks, NULL, 0);
		return KFAILURE;
	}

    #ifdef KRB4
        r = k4_auth_send (ks);
    #endif /* KRB4 */
    
    #ifdef KRB5
        r = k5_auth_send (auth_how);
    #endif /* KRB5 */

    if (! r)
        return KFAILURE;

    plen = strlen (szUserName);                 // Set by k#_send if needed
    pname = szUserName;

	wsprintf(buf, "%c%c%c%c", IAC, SB, AUTHENTICATION, NAME);
	memcpy (&buf[4], pname, plen);
	wsprintf(&buf[plen + 4], "%c%c", IAC, SE);
	TelnetSend(ks, (LPSTR)buf, lstrlen(pname)+6, 0);

	wsprintf(buf, "%c%c%c%c%c%c%c", IAC, SB, AUTHENTICATION, IS,
		KERBEROS_VERSION, auth_how | AUTH_CLIENT_TO_SERVER, AUTH);

    #if KRB4
    	auth.length = copy_for_net(&buf[7], auth.dat, auth.length);
    #endif /* KRB4 */
    #if KRB5
    	auth.length = copy_for_net(&buf[7], auth.data, auth.length);
    #endif /* KRB5 */

	wsprintf(&buf[auth.length+7], "%c%c", IAC, SE);

	TelnetSend(ks, (LPSTR)buf, auth.length+9, 0);

	return KSUCCESS;

}	/* auth_send */

/*+
 * Function: Parse authentication reply command
 *
 * Parameters:
 *	ks - kstream to send abort message to.
 *
 *  parsedat - the sub-command data.
 *
 *	end_sub - index of the character in the 'parsedat' array which
 *		is the last byte in a sub-negotiation
 *
 * Returns: Kerberos error code.
 */
static int
auth_reply(
	kstream ks,
	unsigned char *parsedat,
	int end_sub)
{
    int n;

    #ifdef KRB4
        n = k4_auth_reply (ks, parsedat, end_sub);
    #endif

    #ifdef KRB5
        n = k5_auth_reply (auth_how, parsedat, end_sub);
    #endif

    return n;
}

/*+
 * Function: Parse the athorization sub-options and reply.
 *
 * Parameters:
 *	ks - kstream to send abort message to.
 *
 *	parsedat - sub-option string to parse.
 *
 *	end_sub - last charcter position in parsedat.
 */
void
auth_parse(
	kstream ks,
	unsigned char *parsedat,
	int end_sub)
{
	if (parsedat[1] == SEND)
		auth_send(ks, parsedat, end_sub);

	if (parsedat[1] == REPLY)
		auth_reply(ks, parsedat, end_sub);

} /* auth_parse */


/*+
 * Function: Initialization routine called kstream encryption system.
 *
 * Parameters:
 *	str - kstream to send abort message to.
 *
 *  data - user data.
 */
int INTERFACE
auth_init(
	kstream str,
	kstream_ptr data)
{
	return 0;

} /* auth_init */


/*+
 * Function: Destroy routine called kstream encryption system.
 *
 * Parameters:
 *	str - kstream to send abort message to.
 *
 *  data - user data.
 */
void INTERFACE
auth_destroy(
	kstream str)
{
} /* auth_destroy */


/*+
 * Function: Callback to encrypt a block of characters
 *
 * Parameters:
 *	out - return as pointer to converted buffer.
 *
 *  in - the buffer to convert
 *
 *  str - the stream being encrypted
 *
 * Returns: number of characters converted.
 */
int INTERFACE
auth_encrypt(
	struct kstream_data_block *out,
	struct kstream_data_block *in,
	kstream str)
{
	out->ptr = in->ptr;

	out->length = in->length;

	return(out->length);

} /* auth_encrypt */


/*+
 * Function: Callback to decrypt a block of characters
 *
 * Parameters:
 *	out - return as pointer to converted buffer.
 *
 *  in - the buffer to convert
 *
 *  str - the stream being encrypted
 *
 * Returns: number of characters converted.
 */
int INTERFACE
auth_decrypt(
	struct kstream_data_block *out,
	struct kstream_data_block *in,
	kstream str)
{
	out->ptr = in->ptr;

	out->length = in->length;

	return(out->length);

} /* auth_decrypt */

/*++*/
#ifdef KRB4
/*
** 
** K4_auth_send - gets authentication bits we need to send to KDC.
** 
** Result is left in auth
**
** Returns: 0 on failure, 1 on success
*/
static int
k4_auth_send (
	kstream ks)
{
    int r;                                      // Return value
    char instance[INST_SZ];
    char *realm;
    char buf[256];

    memset(instance, 0, sizeof(instance));

    if (realm = krb_get_phost(szHostName))
        lstrcpy(instance, realm);

    realm = krb_realmofhost(szHostName);

    if (!realm) {
        strcpy(buf, "Can't find realm for host \"");
        strcat(buf, szHostName);
        strcat(buf, "\"");
        auth_abort(ks, buf, 0);
        return KFAILURE;
    }

    r = krb_mk_req(&auth, KRB_SERVICE_NAME, instance, realm, 0);

    if (r == 0)
        r = krb_get_cred(KRB_SERVICE_NAME, instance, realm, &cred);

    if (r) {
        strcpy(buf, "Can't get \"");
        strcat(buf, KRB_SERVICE_NAME);
        if (instance[0] != 0) {
            strcat(buf, ".");
            lstrcat(buf, instance);
        }
        strcat(buf, "@");
        lstrcat(buf, realm);
        strcat(buf, "\" ticket");
        auth_abort(ks, buf, r);

        return r;
    }

    if (!szUserName[0])					// Copy if not there
        strcpy (szUserName, cred.pname);

	return(1);
}

/*+
 * Function: K4 parse authentication reply command
 *
 * Parameters:
 *	ks - kstream to send abort message to.
 *
 *  parsedat - the sub-command data.
 *
 *	end_sub - index of the character in the 'parsedat' array which
 *		is the last byte in a sub-negotiation
 *
 * Returns: Kerberos error code.
 */
static int
k4_auth_reply(
	kstream ks,
	unsigned char *parsedat,
	int end_sub)
{
	time_t t;
	int x;
    char buf[512];
	int i;
    des_cblock session_key;
    des_key_schedule sched;
    static des_cblock challenge;

	if (end_sub < 4)
		return KFAILURE;
		
	if (parsedat[2] != KERBEROS_V4)
		return KFAILURE;

	if (parsedat[4] == K4_REJECT) {
		buf[0] = 0;

		for (i = 5; i <= end_sub; i++) {
			if (parsedat[i] == IAC)
				break;
			buf[i-5] = parsedat[i];
			buf[i-4] = 0;
		}

		if (!buf[0])
			strcpy(buf, "Authentication rejected by remote machine!");
		MessageBox(HWND_DESKTOP, buf, NULL, MB_OK | MB_ICONEXCLAMATION);

		return KFAILURE;
	}

	if (parsedat[4] == K4_ACCEPT) {
		if ((parsedat[3] & AUTH_HOW_MASK) == AUTH_HOW_ONE_WAY)
			return KSUCCESS;

		if ((parsedat[3] & AUTH_HOW_MASK) != AUTH_HOW_MUTUAL)
			return KFAILURE;

        des_key_sched(cred.session, sched);

		t = time(NULL);
		memcpy(challenge, &t, 4);
		memcpy(&challenge[4], &t, 4);
        des_ecb_encrypt(&challenge, &session_key, sched, 1);

		/*
		* Increment the challenge by 1, and encrypt it for
		* later comparison.
		*/
		for (i = 7; i >= 0; --i) {
			x = (unsigned int)challenge[i] + 1;
			challenge[i] = x;	/* ignore overflow */
			if (x < 256)		/* if no overflow, all done */
				break;
		}

        des_ecb_encrypt(&challenge, &challenge, sched, 1);

		wsprintf(buf, "%c%c%c%c%c%c%c", IAC, SB, AUTHENTICATION, IS,
			KERBEROS_V4, AUTH_CLIENT_TO_SERVER|AUTH_HOW_MUTUAL, K4_CHALLENGE);
		memcpy(&buf[7], session_key, 8);
		wsprintf(&buf[15], "%c%c", IAC, SE);
		TelnetSend(ks, (LPSTR)buf, 17, 0);

		return KSUCCESS;
	}

	if (parsedat[4] == K4_RESPONSE) {
		if (end_sub < 12)
			return KFAILURE;

		if (memcmp(&parsedat[5], challenge, sizeof(challenge)) != 0) {
	    	MessageBox(HWND_DESKTOP, "Remote machine is being impersonated!",
			   NULL, MB_OK | MB_ICONEXCLAMATION);

			return KFAILURE;
		}

		return KSUCCESS;
	}
	
	return KFAILURE;

} /* auth_reply */

#endif /* KRB4 */
/*++*/
#ifdef KRB5

/*
** 
** K5_auth_send - gets authentication bits we need to send to KDC.
** 
** Code lifted from telnet sample code in the appl directory.
**  
** Result is left in auth
**
** Returns: 0 on failure, 1 on success
** 
*/

static int 
k5_auth_send (int how)
{
	krb5_error_code r;
	krb5_ccache ccache;
    krb5_creds cred;
	krb5_creds * new_cred;
	extern krb5_flags krb5_kdc_default_options;
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

	r = krb5_mk_req_extended(k5_context, &auth_context, ap_opts,
				 NULL, new_cred, &auth);

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

    data += 4;                                  /* Point to status byte */

	switch (*data++) {
	case K5_REJECT:
        if (cnt > 0)
            wsprintf (strTmp,
                "Kerberos V5 refuses authentication because %.*s",
                cnt, data);
		else
			wsprintf (strTmp, "Kerberos V5 refuses authentication");
        MessageBox (HWND_DESKTOP, strTmp, "", MB_OK | MB_ICONEXCLAMATION);

		return KFAILURE;

	case K5_ACCEPT:
		if ((how & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL && !mutual_complete) {
		    wsprintf(strTmp, "Kerberos V5 accepted you, " 
              "but didn't provide mutual authentication");
            MessageBox (HWND_DESKTOP, strTmp, "", MB_OK | MB_ICONEXCLAMATION);
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

		    if (r = krb5_rd_rep (k5_context, auth_context, &inbuf, &reply)) {
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
#endif /* KRB5 */
