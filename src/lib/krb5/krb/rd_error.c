/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_rd_error() routine
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rd_error_c[] =
"$Id$";
#endif	/* !lint & !SABER */


#include <krb5/krb5.h>
#include <krb5/asn1.h>

#include <krb5/ext-proto.h>

/*
 *  Parses an error message from enc_errbuf and returns an allocated
 * structure which contain the error message.
 *
 *  Upon return dec_error will point to allocated storage which the
 * caller should free when finished.
 * 
 *  returns system errors
 */

krb5_error_code
krb5_rd_error( enc_errbuf, dec_error)
const krb5_data *enc_errbuf;
krb5_error **dec_error;
{
    if (!krb5_is_krb_error(enc_errbuf))
	return KRB5KRB_AP_ERR_MSG_TYPE;
    return(decode_krb5_error(enc_errbuf, dec_error));
}

