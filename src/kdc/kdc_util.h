/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Declarations for policy.c
 */

#include <krb5/copyright.h>

#ifndef __KRB5_KDC_UTIL__
#define __KRB5_KDC_UTIL__

krb5_error_code check_hot_list PROTOTYPE((krb5_ticket *));
krb5_boolean realm_compare PROTOTYPE((krb5_data *, krb5_principal));
krb5_error_code compress_transited PROTOTYPE((krb5_data,
					      krb5_principal,
					      krb5_data *));
krb5_error_code concat_authorization_data PROTOTYPE((krb5_authdata **,
						     krb5_authdata **,
						     krb5_authdata ***));
krb5_error_code fetch_last_req_info PROTOTYPE((krb5_db_entry *,
					       krb5_last_req_entry ***));

krb5_error_code kdc_convert_key PROTOTYPE((krb5_keyblock *,
					   krb5_keyblock *,
					   int));
krb5_error_code decrypt_tgs_req PROTOTYPE((krb5_tgs_req *));

/* which way to convert key? */
#define CONVERT_INTO_DB	0
#define CONVERT_OUTOF_DB 1

#define isset(flagfield, flag) (flagfield & (flag))
#define set(flagfield, flag) (flagfield |= (flag))
#define clear(flagfield, flag) (flagfield &= ~(flag))

#define realm_of_tgt(ticket) ((ticket)->server[0])

#ifndef	min
#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

#endif /* __KRB5_KDC_UTIL__ */
