/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_mk_error() routine.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_mk_error_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/asn1.h>

/*
 formats the error structure *dec_err into an error buffer *enc_err.

 The error buffer storage is allocated, and should be freed by the
 caller when finished.

 returns system errors
 */
krb5_error_code
krb5_mk_error(dec_err, enc_err)
krb5_error *dec_err;
krb5_data **enc_err;
{
    return (encode_krb5_error(dec_err, enc_err));
}
