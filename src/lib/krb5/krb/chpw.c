/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
** set password functions added by Paul W. Nelson, Thursby Software Systems, Inc.
*/
#include <string.h>

#include "k5-int.h"
#include "int-proto.h"
#include "auth_con.h"


krb5_error_code
krb5int_mk_chpw_req(krb5_context context,
                    krb5_auth_context auth_context,
                    krb5_data *ap_req,
                    char *passwd,
                    krb5_data *packet)
{
    krb5_error_code ret = 0;
    krb5_data clearpw;
    krb5_data cipherpw;
    krb5_replay_data replay;
    char *ptr;

    cipherpw.data = NULL;

    if ((ret = krb5_auth_con_setflags(context, auth_context,
                                      KRB5_AUTH_CONTEXT_DO_SEQUENCE)))
        goto cleanup;

    clearpw.length = strlen(passwd);
    clearpw.data = passwd;

    if ((ret = krb5_mk_priv(context, auth_context,
                            &clearpw, &cipherpw, &replay)))
        goto cleanup;

    packet->length = 6 + ap_req->length + cipherpw.length;
    packet->data = (char *) malloc(packet->length);
    if (packet->data == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }
    ptr = packet->data;

    /* length */

    store_16_be(packet->length, ptr);
    ptr += 2;

    /* version == 0x0001 big-endian */

    *ptr++ = 0;
    *ptr++ = 1;

    /* ap_req length, big-endian */

    store_16_be(ap_req->length, ptr);
    ptr += 2;

    /* ap-req data */

    memcpy(ptr, ap_req->data, ap_req->length);
    ptr += ap_req->length;

    /* krb-priv of password */

    memcpy(ptr, cipherpw.data, cipherpw.length);

cleanup:
    if (cipherpw.data != NULL)  /* allocated by krb5_mk_priv */
        free(cipherpw.data);

    return(ret);
}

/* Decode error_packet as a KRB-ERROR message and retrieve its e-data into
 * *edata_out. */
static krb5_error_code
get_error_edata(krb5_context context, const krb5_data *error_packet,
                krb5_data **edata_out)
{
    krb5_error_code ret;
    krb5_error *krberror = NULL;

    *edata_out = NULL;

    ret = krb5_rd_error(context, error_packet, &krberror);
    if (ret)
        return ret;

    if (krberror->e_data.data == NULL) {
        /* Return a krb5 error code based on the error number. */
        ret = ERROR_TABLE_BASE_krb5 + (krb5_error_code)krberror->error;
        goto cleanup;
    }

    ret = krb5_copy_data(context, &krberror->e_data, edata_out);

cleanup:
    krb5_free_error(context, krberror);
    return ret;
}

/* Decode a reply to produce the clear-text output. */
static krb5_error_code
get_clear_result(krb5_context context, krb5_auth_context auth_context,
                 const krb5_data *packet, krb5_data **clear_out,
                 krb5_boolean *is_error_out)
{
    krb5_error_code ret;
    char *ptr, *end = packet->data + packet->length;
    unsigned int plen, vno, aplen;
    krb5_data ap_rep, cipher, error;
    krb5_ap_rep_enc_part *ap_rep_enc;
    krb5_replay_data replay;
    krb5_key send_subkey = NULL;
    krb5_data clear = empty_data();

    *clear_out = NULL;
    *is_error_out = FALSE;

    /* Check for an unframed KRB-ERROR (expected for RFC 3244 requests; also
     * received from MS AD for version 1 requests). */
    if (krb5_is_krb_error(packet)) {
        *is_error_out = TRUE;
        return get_error_edata(context, packet, clear_out);
    }

    if (packet->length < 6)
        return KRB5KRB_AP_ERR_MODIFIED;

    /* Decode and verify the length. */
    ptr = packet->data;
    plen = (*ptr++ & 0xff);
    plen = (plen << 8) | (*ptr++ & 0xff);
    if (plen != packet->length)
        return KRB5KRB_AP_ERR_MODIFIED;

    /* Decode and verify the version number. */
    vno = (*ptr++ & 0xff);
    vno = (vno << 8) | (*ptr++ & 0xff);
    if (vno != 1 && vno != 0xff80)
        return KRB5KDC_ERR_BAD_PVNO;

    /* Decode and check the AP-REP length. */
    aplen = (*ptr++ & 0xff);
    aplen = (aplen << 8) | (*ptr++ & 0xff);
    if (aplen > end - ptr)
        return KRB5KRB_AP_ERR_MODIFIED;

    /* A zero-length AP-REQ indicates a framed KRB-ERROR response.  (Expected
     * for protocol version 1; specified but unusual for RFC 3244 requests.) */
    if (aplen == 0) {
        *is_error_out = TRUE;
        error = make_data(ptr, end - ptr);
        return get_error_edata(context, &error, clear_out);
    }

    /* We have an AP-REP.  Save send_subkey to later smash recv_subkey. */
    ret = krb5_auth_con_getsendsubkey_k(context, auth_context, &send_subkey);
    if (ret)
        return ret;

    /* Verify the AP-REP. */
    ap_rep = make_data(ptr, aplen);
    ptr += ap_rep.length;
    ret = krb5_rd_rep(context, auth_context, &ap_rep, &ap_rep_enc);
    if (ret)
        goto cleanup;
    krb5_free_ap_rep_enc_part(context, ap_rep_enc);

    /* Smash recv_subkey to be send_subkey, per spec. */
    ret = krb5_auth_con_setrecvsubkey_k(context, auth_context, send_subkey);
    if (ret)
        goto cleanup;

    /* Extract and decrypt the result. */
    cipher = make_data(ptr, end - ptr);
    ret = krb5_rd_priv(context, auth_context, &cipher, &clear, &replay);
    if (ret)
        goto cleanup;

    ret = krb5_copy_data(context, &clear, clear_out);
    if (ret)
        goto cleanup;
    *is_error_out = FALSE;

cleanup:
    krb5_k_free_key(context, send_subkey);
    krb5_free_data_contents(context, &clear);
    return ret;
}

krb5_error_code
krb5int_rd_chpw_rep(krb5_context context, krb5_auth_context auth_context,
                    krb5_data *packet, int *result_code_out,
                    krb5_data *result_data_out)
{
    krb5_error_code ret;
    krb5_data result_data, *clear = NULL;
    krb5_boolean is_error;
    char *ptr;
    int result_code;

    *result_code_out = 0;
    *result_data_out = empty_data();

    ret = get_clear_result(context, auth_context, packet, &clear, &is_error);
    if (ret)
        return ret;

    if (clear->length < 2) {
        ret = KRB5KRB_AP_ERR_MODIFIED;
        goto cleanup;
    }

    /* Decode and check the result code. */
    ptr = clear->data;
    result_code = (*ptr++ & 0xff);
    result_code = (result_code << 8) | (*ptr++ & 0xff);
    if (result_code < KRB5_KPASSWD_SUCCESS ||
        result_code > KRB5_KPASSWD_INITIAL_FLAG_NEEDED) {
        ret = KRB5KRB_AP_ERR_MODIFIED;
        goto cleanup;
    }

    /* Successful replies must not come from errors. */
    if (is_error && result_code == KRB5_KPASSWD_SUCCESS) {
        ret = KRB5KRB_AP_ERR_MODIFIED;
        goto cleanup;
    }

    result_data = make_data(ptr, clear->data + clear->length - ptr);
    ret = krb5int_copy_data_contents(context, &result_data, result_data_out);
    if (ret)
        goto cleanup;
    *result_code_out = result_code;

cleanup:
    krb5_free_data(context, clear);
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_chpw_result_code_string(krb5_context context, int result_code,
                             char **code_string)
{
    switch (result_code) {
    case KRB5_KPASSWD_MALFORMED:
        *code_string = _("Malformed request error");
        break;
    case KRB5_KPASSWD_HARDERROR:
        *code_string = _("Server error");
        break;
    case KRB5_KPASSWD_AUTHERROR:
        *code_string = _("Authentication error");
        break;
    case KRB5_KPASSWD_SOFTERROR:
        *code_string = _("Password change rejected");
        break;
    case KRB5_KPASSWD_ACCESSDENIED:
        *code_string = _("Access denied");
        break;
    case KRB5_KPASSWD_BAD_VERSION:
        *code_string = _("Wrong protocol version");
        break;
    case KRB5_KPASSWD_INITIAL_FLAG_NEEDED:
        *code_string = _("Initial password required");
        break;
    default:
        *code_string = _("Password change failed");
        break;
    }

    return 0;
}

krb5_error_code
krb5int_mk_setpw_req(krb5_context context,
                     krb5_auth_context auth_context,
                     krb5_data *ap_req,
                     krb5_principal targprinc,
                     char *passwd,
                     krb5_data *packet)
{
    krb5_error_code ret;
    krb5_data   cipherpw;
    krb5_data   *encoded_setpw;
    struct krb5_setpw_req req;

    char *ptr;

    cipherpw.data = NULL;
    cipherpw.length = 0;

    if ((ret = krb5_auth_con_setflags(context, auth_context,
                                      KRB5_AUTH_CONTEXT_DO_SEQUENCE)))
        return(ret);

    req.target = targprinc;
    req.password.data = passwd;
    req.password.length = strlen(passwd);
    ret = encode_krb5_setpw_req(&req, &encoded_setpw);
    if (ret) {
        return ret;
    }

    if ((ret = krb5_mk_priv(context, auth_context, encoded_setpw, &cipherpw, NULL)) != 0) {
        krb5_free_data(context, encoded_setpw);
        return(ret);
    }
    krb5_free_data(context, encoded_setpw);


    packet->length = 6 + ap_req->length + cipherpw.length;
    packet->data = (char *) malloc(packet->length);
    if (packet->data  == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }
    ptr = packet->data;
    /*
    ** build the packet -
    */
    /* put in the length */
    store_16_be(packet->length, ptr);
    ptr += 2;
    /* put in the version */
    *ptr++ = (char)0xff;
    *ptr++ = (char)0x80;
    /* the ap_req length is big endian */
    store_16_be(ap_req->length, ptr);
    ptr += 2;
    /* put in the request data */
    memcpy(ptr, ap_req->data, ap_req->length);
    ptr += ap_req->length;
    /*
    ** put in the "private" password data -
    */
    memcpy(ptr, cipherpw.data, cipherpw.length);
    ret = 0;
cleanup:
    if (cipherpw.data)
        krb5_free_data_contents(context, &cipherpw);
    if ((ret != 0) && packet->data) {
        free(packet->data);
        packet->data = NULL;
    }
    return ret;
}
