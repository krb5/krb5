/*
 * lib/gssapi/krb5/set_ccache.c
 *
 * Copyright 1999, 2003 by the Massachusetts Institute of Technology.
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
 * Set ccache name used by gssapi, and optionally obtain old ccache
 * name.  Caller should not free returned name.
 */

#include <string.h>
#include "gssapiP_krb5.h"

OM_uint32 KRB5_CALLCONV 
gss_krb5_ccache_name(minor_status, name, out_name)
	OM_uint32 *minor_status;
	const char *name;
	const char **out_name;
{
	krb5_context context;
	krb5_error_code retval;
	static char *oldname = NULL;
	const char *tmpname = NULL;

	if (GSS_ERROR(kg_get_context(minor_status, &context)))
		return (GSS_S_FAILURE);

	if (out_name) {
		if (oldname != NULL)
			free(oldname);
		/*
		 * Save copy of previous default ccname, since
		 * cc_set_default_name will free it and we don't want
		 * to hang on to a pointer to freed memory.
		 */
		tmpname = krb5_cc_default_name(context);
		oldname = malloc(strlen(tmpname) + 1);
		if (oldname == NULL)
			return GSS_S_FAILURE;
		strcpy(oldname, tmpname);
		*out_name = oldname;
	}

	retval = krb5_cc_set_default_name(context, name);
	if (retval) {
		*minor_status = retval;
		return GSS_S_FAILURE;
	}
	return GSS_S_COMPLETE;
}
