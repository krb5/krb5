/*
 * lib/krb5/os/init_ctx.c
 *
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * krb5_init_contex()
 */

#include <krb5/krb5.h>
#include <krb5/libos.h>
#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>

krb5_error_code
krb5_os_init_context(ctx)
	krb5_context *ctx;
{
	krb5_os_context *os_ctx;
	
	if (ctx->os_context)
		return 0;

	os_ctx = malloc(sizeof(struct _krb5_os_context));
	if (!os_ctx)
		return ENOMEM;
	memset(os_ctx, 0, sizeof(struct _krb5_os_context));
	os_ctx->magic = KV5M_OS_CONTEXT;

	ctx->os_context = (void *) os_ctx;
	
	return 0;
}

void
krb5_free_os_context(ctx)
	krb5_context	*ctx;
{
	krb5_os_context *os_ctx;

	os_ctx = ctx->os_context;
	
	if (!os_ctx)
		return;

	os_ctx->magic = 0;
	free(os_ctx);
	ctx->os_context = 0;
}
