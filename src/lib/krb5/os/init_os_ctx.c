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

#define NEED_WINDOWS
#include "k5-int.h"

krb5_error_code
krb5_os_init_context(ctx)
	krb5_context ctx;
{
	krb5_os_context os_ctx;
	krb5_error_code	retval = 0;
	char *name;
	const char *filenames[2];
	
	if (ctx->os_context)
		return 0;

	os_ctx = malloc(sizeof(struct _krb5_os_context));
	if (!os_ctx)
		return ENOMEM;
	memset(os_ctx, 0, sizeof(struct _krb5_os_context));
	os_ctx->magic = KV5M_OS_CONTEXT;

	ctx->os_context = (void *) os_ctx;

	os_ctx->time_offset = 0;
	os_ctx->usec_offset = 0;
	os_ctx->os_flags = 0;

#ifdef _WINDOWS
    {
        char defname[160];                      /* Default value */
        char krb5conf[160];                     /* Actual value */

        GetWindowsDirectory(defname, sizeof(defname) - 10);
        strcat (defname, "\\");
        strcat (defname, DEFAULT_PROFILE_FILENAME);
        GetPrivateProfileString(INI_FILES, INI_KRB5_CONF, defname,
            krb5conf, sizeof(krb5conf), KERBEROS_INI);
        name = krb5conf;

        filenames[0] = name;
        filenames[1] = 0;
    }

#else /* _WINDOWS */

	/*
	 * When the profile routines are later enhanced, we will try
	 * including a config file from user's home directory here.
	 */
	name = getenv("KRB5_CONFIG");
	filenames[0] = name ? name : DEFAULT_PROFILE_FILENAME;
	filenames[1] = 0;

#endif /* _WINDOWS */

	retval = profile_init(filenames, &ctx->profile);
	if (retval)
	    ctx->profile = 0;

	/*
	 * We ignore errors if the profile can not be initialized,
	 * since there must be a way to get a context even if the
	 * default krb5.conf file doesn't exist.
	 */

	return 0;
}

krb5_error_code INTERFACE
krb5_set_config_files(ctx, filenames)
	krb5_context ctx;
	const char **filenames;
{
	krb5_error_code retval;
	profile_t	profile;
	
	retval = profile_init(filenames, &profile);
	if (retval)
		return retval;

	if (ctx->profile)
		profile_release(ctx->profile);
	ctx->profile = profile;

	return 0;
}

void
krb5_os_free_context(ctx)
	krb5_context	ctx;
{
	krb5_os_context os_ctx;

	os_ctx = ctx->os_context;
	
	if (!os_ctx)
		return;

	os_ctx->magic = 0;
	free(os_ctx);
	ctx->os_context = 0;

	if (ctx->profile)
	    profile_release(ctx->profile);
}
