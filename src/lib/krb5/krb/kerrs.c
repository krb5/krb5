/*
 * lib/krb5/krb/kerrs.c
 *
 * Copyright 2006 Massachusetts Institute of Technology.
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
 * error-message functions
 */
#include <stdarg.h>
#include "k5-int.h"

void
krb5_set_error_message (krb5_context ctx, krb5_error_code code,
			const char *fmt, ...)
{
    va_list args;
    if (ctx == NULL)
	return;
    va_start (args, fmt);
    krb5int_vset_error (&ctx->err, code, fmt, args);
    va_end (args);
}

void
krb5_vset_error_message (krb5_context ctx, krb5_error_code code,
			 const char *fmt, va_list args)
{
    if (ctx == NULL)
	return;
    krb5int_vset_error (&ctx->err, code, fmt, args);
}

char *
krb5_get_error_message (krb5_context ctx, krb5_error_code code)
{
    if (ctx == NULL)
	return error_message(code);
    return krb5int_get_error (&ctx->err, code);
}

void
krb5_free_error_message (krb5_context ctx, char *msg)
{
    if (ctx == NULL)
	return;
    krb5int_free_error (&ctx->err, msg);
}

void
krb5_clear_error_message (krb5_context ctx)
{
    if (ctx == NULL)
	return;
    krb5int_clear_error (&ctx->err);
}
