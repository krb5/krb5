/*+*************************************************************************
** 
** k5passwd
** 
** Changes your password in the Kerberos V5. This should have been
** part of the kadm stuff but we're forced to build a nicer API on top
** of the calls they provide.
** 
***************************************************************************/
#ifdef KRB5
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "krb5.h"
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"

static const char *kadm_replies[] = {
	"Operation successful",             	/* KRB5_ADM_SUCCESS */
	"Command not recognized",           	/* KRB5_ADM_CMD_UNKNOWN */
	"Password unacceptable to server",  	/* KRB5_ADM_PW_UNACCEPT */
	"Old password incorrect",           	/* KRB5_ADM_BAD_PW */
	"Invalid ticket (TKT_FLAG_INITIAL not set)",/* KRB5_ADM_NOT_IN_TKT */
	"Server refused password change",   	/* KRB5_ADM_CANT_CHANGE */
	"Language not supported",				/* KRB5_ADM_LANG_NOT_SUPPORTED */
};
static const char *kadm_replies_unknown = "UNKNOWN ERROR";
static char errbuf[1024];					/* For response from kadm */

/*+*************************************************************************
** 
** get_admin_response
** 
** Builds into a static buffer the replies sent back by the admin server.
** 
***************************************************************************/
static char *
get_admin_response (
	krb5_int32 		status,						// Type of error
	krb5_int32 		nreplies,					// Size of reply
	krb5_data *		reply)						// Buffer of messages
{
	char *ptr;									// For building the response
	char *end = errbuf + sizeof (errbuf);		// So we don't overflow
	int i;										// Index
	int n;										// Length

	if (status <= KRB5_ADM_LANG_NOT_SUPPORTED)	// Is it of a known type???
		strcpy (errbuf, kadm_replies[status]);
	else
		strcpy (errbuf, kadm_replies_unknown);	// Unknown error type
	ptr = errbuf + strlen (errbuf);				// Point at the end

	if (nreplies > 0) {							// Are there more message?
		*ptr++ = ':';
		*ptr = '\0';
	}

	for (i = 0; i < nreplies; ++i) {			// Append additional messages
		*ptr++ = '\n';

		n = reply[i].length;					// Easier to work with
		if (ptr + n + 2 >= errbuf)				// Check for overflow
			break;
		memcpy (ptr, reply[i].data, n);			// Add the message
		ptr += n;								// Point to the end
		*ptr = '\0';
	}

	return errbuf;
}
/*+*************************************************************************
** 
** keyadmin_send_recieve
** 
** Sends a command to the key admin and reads the reply.
** 
***************************************************************************/
static krb5_error_code
keyadmin_send_receive (
	krb5_context 		k5context,
	int *				conn_socket,
	krb5_auth_context 	auth_context,
	krb5_int32 			nargs,
	krb5_data *			arglist,
	krb5_int32 *		cmd_stat,
	krb5_int32 *		nreplies,
	krb5_data **		reply)
{
	krb5_error_code	kret;

	kret = krb5_send_adm_cmd (k5context, conn_socket, auth_context,
		nargs, 	arglist);

	if (! kret)
		kret = krb5_read_adm_reply (k5context, conn_socket, auth_context,
			cmd_stat, nreplies, reply);

	return kret;
}
/*+*************************************************************************
** 
** k5_change_password
** 
** Bundles all the crude needed to change the password into one file.
** 
***************************************************************************/
krb5_error_code
k5_change_password (
    krb5_context k5context,
	char *user,
	char *realm,
	char *opasswd,
	char *npasswd,
    char **text)
{
	krb5_error_code		kret, kret2;
	krb5_auth_context  auth_context;
	krb5_ccache			ccache;
	int					conn_socket;			/* Socket for talking over */
	krb5_int32			nreplies;
	krb5_data			data[3];
	krb5_data * 		reply;
	krb5_int32			status;
	char *				name;

	*text = NULL;								/* Be safe */
	name = malloc (strlen (user) + strlen (realm) + 2);
	if (name == NULL)
		return ENOMEM;
	sprintf (name, "%s@%s", user, realm);
	ccache = (krb5_ccache) NULL;

/*
** Establish the connection.
*/
	kret = krb5_adm_connect (k5context, name,	NULL, opasswd, &conn_socket,
							&auth_context, &ccache, NULL, 0);
	if (kret)
		goto done;
/*
** Check to see if it's an acceptable password
*/
	data[0].data = KRB5_ADM_CHECKPW_CMD;
	data[0].length = strlen (data[0].data);
	data[1].data = npasswd;
	data[1].length = strlen (npasswd);

	kret = keyadmin_send_receive (k5context, &conn_socket, auth_context,
		2, data, &status, &nreplies, &reply);
	if (kret) 									/* Some external error */
		goto cleanup;

	if (status != KRB5_ADM_SUCCESS) {			/* Some problem??? */
		kret = status;
		*text = get_admin_response (status, nreplies, reply);
		krb5_free_adm_data (k5context, nreplies, reply);

		goto quit;
	}
	krb5_free_adm_data (k5context, nreplies, reply);

/*
** The new password is ok, so now actually change the password
*/
	data[0].data = KRB5_ADM_CHANGEPW_CMD;
	data[0].length = strlen (data[0].data);
	data[1].data = opasswd;
	data[1].length = strlen (opasswd);
	data[2].data = npasswd;
	data[2].length = strlen (npasswd);

	kret = keyadmin_send_receive (k5context, &conn_socket, auth_context,
		3, data, &status, &nreplies, &reply);
	if (kret)
		goto cleanup;

	if (status != KRB5_ADM_SUCCESS) {
		kret = status;
		*text = get_admin_response (status, nreplies, reply);
		krb5_free_adm_data (k5context, nreplies, reply);

		goto quit;
	}

	krb5_free_adm_data (k5context, nreplies, reply);
/*+
** Need to send quit command.
*/
 quit:
	data[0].data = KRB5_ADM_QUIT_CMD;
	data[0].length = strlen (data[0].data);

	kret2 = keyadmin_send_receive (k5context, &conn_socket, auth_context,
		1, data, &status, &nreplies, &reply);
	if (kret2) {
		if (! kret)
			kret = kret2;
	} else if (status != KRB5_ADM_SUCCESS) {
		if (! kret)
			kret = status;
		if (*text == NULL)
			*text = get_admin_response (status, nreplies, reply);
	}
	krb5_free_adm_data (k5context, nreplies, reply);

 cleanup:
	krb5_adm_disconnect (k5context, &conn_socket, auth_context, ccache);
 done:
	free (name);

	return kret;
}

#endif /* KRB5 */
