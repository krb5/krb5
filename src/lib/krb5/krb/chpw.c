#include <string.h>

#include "k5-int.h"
#include "krb5_err.h"
#include "auth_con.h"

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_mk_chpw_req(context, auth_context, ap_req, passwd, packet)
     krb5_context context;
     krb5_auth_context auth_context;
     krb5_data *ap_req;
     char *passwd;
     krb5_data *packet;
{
    krb5_error_code ret;
    krb5_data clearpw;
    krb5_data cipherpw;
    krb5_replay_data replay;
    char *ptr;

    if (ret = krb5_auth_con_setflags(context, auth_context,
				     KRB5_AUTH_CONTEXT_DO_SEQUENCE))
	return(ret);

    clearpw.length = strlen(passwd);
    clearpw.data = passwd;

    if (ret = krb5_mk_priv(context, auth_context,
			   &clearpw, &cipherpw, &replay))
    return(ret);

    packet->length = 6 + ap_req->length + cipherpw.length;
    packet->data = (char *) malloc(packet->length);
    if (packet->data == NULL)
	return ENOMEM;
    ptr = packet->data;

    /* length */

    *ptr++ = (packet->length>>8) & 0xff;
    *ptr++ = packet->length & 0xff;

    /* version == 0x0001 big-endian */

    *ptr++ = 0;
    *ptr++ = 1;

    /* ap_req length, big-endian */

    *ptr++ = (ap_req->length>>8) & 0xff;
    *ptr++ = ap_req->length & 0xff;

    /* ap-req data */

    memcpy(ptr, ap_req->data, ap_req->length);
    ptr += ap_req->length;

    /* krb-priv of password */

    memcpy(ptr, cipherpw.data, cipherpw.length);

    return(0);
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_rd_chpw_rep(context, auth_context, packet, result_code, result_data)
     krb5_context context;
     krb5_auth_context auth_context;
     krb5_data *packet;
     int *result_code;
     krb5_data *result_data;
{
    char *ptr;
    int plen, vno;
    krb5_data ap_rep;
    krb5_ap_rep_enc_part *ap_rep_enc;
    krb5_error_code ret;
    krb5_data cipherresult;
    krb5_data clearresult;
    krb5_error *krberror;
    krb5_replay_data replay;
    krb5_keyblock *tmp;

    if (packet->length < 4)
	/* either this, or the server is printing bad messages,
	   or the caller passed in garbage */
	return(KRB5KRB_AP_ERR_MODIFIED);

    ptr = packet->data;

    /* verify length */

    plen = (*ptr++ & 0xff);
    plen = (plen<<8) | (*ptr++ & 0xff);

    if (plen != packet->length)
	return(KRB5KRB_AP_ERR_MODIFIED);

    /* verify version number */

    vno = (*ptr++ & 0xff);
    vno = (vno<<8) | (*ptr++ & 0xff);

    if (vno != 1)
	return(KRB5KDC_ERR_BAD_PVNO);

    /* read, check ap-rep length */

    ap_rep.length = (*ptr++ & 0xff);
    ap_rep.length = (ap_rep.length<<8) | (*ptr++ & 0xff);

    if (ptr + ap_rep.length >= packet->data + packet->length)
	return(KRB5KRB_AP_ERR_MODIFIED);

    if (ap_rep.length) {
	/* verify ap_rep */
	ap_rep.data = ptr;
	ptr += ap_rep.length;

	if (ret = krb5_rd_rep(context, auth_context, &ap_rep, &ap_rep_enc))
	    return(ret);

	krb5_free_ap_rep_enc_part(context, ap_rep_enc);

	/* extract and decrypt the result */

	cipherresult.data = ptr;
	cipherresult.length = (packet->data + packet->length) - ptr;

	/* XXX there's no api to do this right. The problem is that
	   if there's a remote subkey, it will be used.  This is
	   not what the spec requires */

	tmp = auth_context->remote_subkey;
	auth_context->remote_subkey = NULL;

	ret = krb5_rd_priv(context, auth_context, &cipherresult, &clearresult,
			   &replay);

	auth_context->remote_subkey = tmp;

	if (ret)
	    return(ret);
    } else {
	cipherresult.data = ptr;
	cipherresult.length = (packet->data + packet->length) - ptr;

	if (ret = krb5_rd_error(context, &cipherresult, &krberror))
	    return(ret);

	clearresult = krberror->e_data;
    }

    if (clearresult.length < 2) {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }

    ptr = clearresult.data;

    *result_code = (*ptr++ & 0xff);
    *result_code = (*result_code<<8) | (*ptr++ & 0xff);

    if ((*result_code < KRB5_KPASSWD_SUCCESS) ||
	(*result_code > KRB5_KPASSWD_SOFTERROR)) {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }

    /* all success replies should be authenticated/encrypted */

    if ((ap_rep.length == 0) && (*result_code == KRB5_KPASSWD_SUCCESS)) {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }

    result_data->length = (clearresult.data + clearresult.length) - ptr;

    if (result_data->length) {
	result_data->data = (char *) malloc(result_data->length);
	if (result_data->data == NULL) {
	    ret = ENOMEM;
	    goto cleanup;
	}
	memcpy(result_data->data, ptr, result_data->length);
    } else {
	result_data->data = NULL;
    }

    ret = 0;

cleanup:
    if (ap_rep.length) {
	krb5_xfree(clearresult.data);
    } else {
	krb5_free_error(context, krberror);
    }

    return(ret);
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_chpw_result_code_string(context, result_code, code_string)
     krb5_context context;
     int result_code;
     char **code_string;
{
   switch (result_code) {
   case KRB5_KPASSWD_MALFORMED:
      *code_string = "Malformed request error";
      break;
   case KRB5_KPASSWD_HARDERROR:
      *code_string = "Server error";
      break;
   case KRB5_KPASSWD_AUTHERROR:
      *code_string = "Authentication error";
      break;
   case KRB5_KPASSWD_SOFTERROR:
      *code_string = "Password change rejected";
      break;
   default:
      *code_string = "Password change failed";
      break;
   }

   return(0);
}
