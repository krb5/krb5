/*
 *  Copyright 1990,1994 by the Massachusetts Institute of Technology.
 *  All Rights Reserved.
 * 
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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
 */

/*
 * $Id$
 */

/*
 * stub functions for those without the hash library.
 */

#include "gssapiP_generic.h"

#include <sys/types.h>
#include <sys/file.h>
#include <limits.h>

/* functions for each type */

/* save */

int g_save_name(void **vdb, gss_name_t *name)
{
	return 1;
}
int g_save_cred_id(void **vdb, gss_cred_id_t *cred)
{
	return 1;
}
int g_save_ctx_id(void **vdb, gss_ctx_id_t *ctx)
{
	return 1;
}

/* validate */

int g_validate_name(void **vdb, gss_name_t *name)
{
	return 1;
}
int g_validate_cred_id(void **vdb, gss_cred_id_t *cred)
{
	return 1;
}
int g_validate_ctx_id(void **vdb, gss_ctx_id_t *ctx)
{
	return 1;
}

/* delete */

int g_delete_name(void **vdb, gss_name_t *name)
{
	return 1;
}
int g_delete_cred_id(void **vdb, gss_cred_id_t *cred)
{
	return 1;
}
int g_delete_ctx_id(void **vdb, gss_ctx_id_t *ctx)
{
	return 1;
}

