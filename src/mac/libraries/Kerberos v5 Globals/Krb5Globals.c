/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */


/*
 * Definitions for globally shared data used by the Kerberos v5 library
 *
 * $Header$
 */

#include <Errors.h>
 
#include <CCache.h>

#include <string.h>
#include <stdio.h>
 
#include "Krb5Globals.h"
#include "Krb5GlobalsData.h"
#include "Krb5Globals.CFM.h"

/*
 * Set the default cache name
 */

OSStatus
Krb5GlobalsSetDefaultCacheName (
	char*	inName)
{
	char*	newName;
	
	newName = NewPtrSys (strlen (inName) + 1);
	
	if (newName == nil)
		return MemError();
	
	BlockMoveData (inName, newName, strlen (inName) + 1);
	if (gKerberos5SystemDefaultCacheName != nil)
		DisposePtr (gKerberos5SystemDefaultCacheName);
	gKerberos5SystemDefaultCacheName = newName;
	gKerberos5SystemDefaultCacheNameModification++;
	return noErr;
}

/*
 * Get the default cache name 
 */

UInt32
Krb5GlobalsGetDefaultCacheName (
	char*	inName,
	UInt32	inLength)
{
	if (inName != nil) {
		BlockMoveData (gKerberos5SystemDefaultCacheName, inName, inLength);
		inName [inLength] = '\0';
	}
	return strlen (gKerberos5SystemDefaultCacheName) + 1;
}

/*
 * Set the default cache name to something unique 
 * (i.e. not a name of an existing ccache)
 */

OSStatus
Krb5GlobalsSetUniqueDefaultCacheName ()
{
	OSStatus	err = noErr;
	UInt32		i;
	char		name [16];
	cc_uint32	ccErr;
	ccache_p*	ccache;
	
	/* Infinite loop! I presume you won't have 2^32 ccaches... */
	for (i = 0; ;i++) {
		sprintf (name, "%d", i);
		ccErr = cc_open (gCCContext, name, CC_CRED_V5, 0L, &ccache);
		if (ccErr == CC_NO_EXIST) {
			err = Krb5GlobalsSetDefaultCacheName (name);
			break;
		} else if (ccErr == CC_NOERROR) {
			cc_close (gCCContext, &ccache);
		} else {
			err = memFullErr;
			break;
		}
	}
	
	return err;
}

/* 
 * Return the modification number 
 */

UInt32
Krb5GlobalsGetDefaultCacheNameModification ()
{
	return gKerberos5SystemDefaultCacheNameModification;
}