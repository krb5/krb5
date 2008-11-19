/*
 * lib/krb5/krb/pac.c
 *
 * Copyright 2008 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_parse_name() routine.
 *
 * Rewritten by Theodore Ts'o to properly handle arbitrary quoted
 * characters in the principal name.
 */


#include "k5-int.h"
#include "k5-utf8.h"

krb5_error_code KRB5_CALLCONV
krb5_pac_add_buffer(krb5_context context,
		    krb5_pac pac,
		    krb5_ui_4 type,
		    const krb5_data *data)
{
}

void KRB5_CALLCONV
krb5_pac_free(krb5_context context,
	      krb5_pac pac)
{
}

krb5_error_code KRB5_CALLCONV
krb5_pac_get_buffer(krb5_context context,
		    krb5_pac pac,
		    krb5_ui_4 type,
		    krb5_data *data)
{
}

krb5_error_code KRB5_CALLCONV
krb5_pac_get_types(krb5_context context,
		   krb5_pac pac,
		   size_t *len,
		   krb5_ui_4 **types)
{
}

krb5_error_code KRB5_CALLCONV
krb5_pac_init(krb5_context context,
	      krb5_pac *pac)
{
}

krb5_error_code KRB5_CALLCONV
krb5_pac_parse(krb5_context context,
	       const void *ptr,
	       size_t len,
	       krb5_pac *pac)
{
}

krb5_error_code KRB5_CALLCONV
krb5_pac_verify(krb5_context context,
		const krb5_pac pac,
		time_t authtime,
		krb5_const_principal principal,
		const krb5_keyblock *server,
		const krb5_keyblock *privsvr)
{
}

