/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_rd_error() routine
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rd_error_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/asn1.h>

#include <krb5/ext-proto.h>

/*
 Parses an error message from enc_errbuf and fills in the contents of estruct.

 Upon return dec_error->client,server,text, if non-NULL, point to allocated
 storage which the caller should free when finished.

 returns system errors
 */

krb5_error_code
krb5_rd_error( enc_errbuf, dec_error)
krb5_data *enc_errbuf;
krb5_error *dec_error;
{
    krb5_error_code retval;
    krb5_error *new_dec_error;

    if (retval = decode_krb5_error(enc_errbuf, &new_dec_error))
	return(retval);
    *dec_error = *new_dec_error;
    (void)free((char *)new_dec_error);
    return 0;
}

