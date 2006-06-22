/* $Copyright:
 *
 * Copyright 1998-2006 by the Massachusetts Institute of Technology.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require a
 * specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and distribute
 * this software and its documentation for any purpose and without fee is
 * hereby granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of M.I.T. not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  Furthermore if you
 * modify this software you must label your software as modified software
 * and not distribute it in such a fashion that it might be confused with
 * the original MIT software. M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * Individual source code files are copyright MIT, Cygnus Support,
 * OpenVision, Oracle, Sun Soft, FundsXpress, and others.
 * 
 * Project Athena, Athena, Athena MUSE, Discuss, Hesiod, Kerberos, Moira,
 * and Zephyr are trademarks of the Massachusetts Institute of Technology
 * (MIT).  No commercial use of these trademarks may be made without prior
 * written permission of MIT.
 * 
 * "Commercial use" means use of a name in a product or other for-profit
 * manner.  It does NOT prevent a commercial firm from referring to the MIT
 * trademarks in order to convey information (although in doing so,
 * recognition of their trademark status should be given).
 * $
 */
/*
 * This is backwards compatibility for CCache API v2 clients to be able to run 
 * against the CCache API v3 library
 */
 
#include "CredentialsCache2.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

CCACHE_API cc_int32 cc_shutdown (
        apiCB**				ioContext)
{
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_get_NC_info (
	apiCB*				inContext,
	infoNC***			outInfo)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_get_change_time (
	apiCB*				inContext,
	cc_time*			outTime)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_open (
	apiCB*				inContext,
	const char*			inName,
	cc_int32			inVersion,
	cc_uint32			inFlags,
	ccache_p**			outCCache)
{
    if (inVersion != CC_CRED_V4 && inVersion != CC_CRED_V5)
	return CC_ERR_CRED_VERSION;

    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_create (
	apiCB*				inContext,
	const char*			inName,
	const char*			inPrincipal,
	cc_int32			inVersion,
	cc_uint32			inFlags,
	ccache_p**			outCCache)
{
    if (inVersion != CC_CRED_V4 && inVersion != CC_CRED_V5)
	return CC_ERR_CRED_VERSION;
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_close (
	apiCB*				inContext,
	ccache_p**			ioCCache)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_destroy (
	apiCB*				inContext,
	ccache_p**			ioCCache)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_seq_fetch_NCs_begin (
	apiCB*				inContext,
	ccache_cit**			outIterator)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_seq_fetch_NCs_next (
	apiCB*				inContext,
	ccache_p**			outCCache,
	ccache_cit*			inIterator)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_seq_fetch_NCs_end (
	apiCB*				inContext,
	ccache_cit**			ioIterator)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_get_name (
	apiCB*				inContext,
	ccache_p*			inCCache,
	char**				outName)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_get_cred_version (
	apiCB*				inContext,
	ccache_p*			inCCache,
	cc_int32*			outVersion)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_set_principal (
	apiCB*				inContext,
	ccache_p*			inCCache,
	cc_int32			inVersion,
	char*				inPrincipal)
{
    if (inVersion != CC_CRED_V4 && inVersion != CC_CRED_V5)
	return CC_ERR_CRED_VERSION;
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_get_principal (
	apiCB*				inContext,
	ccache_p*			inCCache,
	char**				outPrincipal)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_store (
	apiCB*				inContext,
	ccache_p*			inCCache,
	cred_union			inCredentials)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_remove_cred (
	apiCB*				inContext,
	ccache_p*			inCCache,
	cred_union			inCredentials)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_seq_fetch_creds_begin (
	apiCB*				inContext,
	const ccache_p*			inCCache,
	ccache_cit**			outIterator)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_seq_fetch_creds_next (
	apiCB*				inContext,
	cred_union**			outCreds,
	ccache_cit*			inIterator)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_seq_fetch_creds_end (
	apiCB*				inContext,
	ccache_cit**			ioIterator)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}
	
CCACHE_API cc_int32 cc_free_principal (
	apiCB*				inContext,
	char**				ioPrincipal)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_free_name (
	apiCB*				inContext,
	char**				ioName)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_free_creds (
	apiCB*				inContext,
	cred_union**			creds)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_free_NC_info (
	apiCB*				inContext,
	infoNC***			ioInfo)
{
	
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}

CCACHE_API cc_int32 cc_lock_request(
        apiCB* 				inContext,
        const ccache_p* 		inCCache,
        const cc_int32 			lock_type)
{
    /* replace this return value when the function is implemented */
    return CC_NOT_SUPP;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */

