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
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */


/*
 * Definitions for globally shared data used by the Kerberos v5 library
 *
 * $Header$
 */

#include <Types.h>
#include <Errors.h>
#include <CCache2.h>
#include <CodeFragments.h>

 
#include "Krb5GlobalsData.h"
#include "Krb5Globals.CFM.h"

apiCB*	gCCContext = nil;

/* $Header$ */

/*	Include MITAthenaCore for:
	 - prototypes for __initialize and __terminate
	 - resource-fork access utilities for shared libraries
 */

#if defined(__CFM68K__) && !defined(__USING_STATIC_LIBS__)
#	pragma import on
#endif

	pascal OSErr __initialize (const CFragInitBlock*	theInitBlock);
	pascal void __terminate (void);

/*	Standard CFM initializion function prototype */
pascal OSErr
__initialize_Kerberos5GlobalsLib (
	CFragInitBlockPtr	inInitBlock);

/*	Standard CFM termination function prototype */
pascal void
__terminate_Kerberos5GlobalsLib (
	void);

/*	CFM magic again */	
#if defined(__CFM68K__) && !defined(__USING_STATIC_LIBS__)
#	pragma import reset
#endif

/*	This is the initialization function.
	This function is guaranteed to be called every time the library is prepared -- which
	is whenever an application is launched that uses the library
	In order for this to happen, the function name must be entered in the "Initialization function"
	field in PPC and CFM-68K linker preferences.
	
	If this function returns an error code, preparation of the library fails. When preparation fails,
	either the Finder displays an error message (in the case of strong linking) or library is not loaded
	(in the case of weak linking).
*/
pascal OSErr
__initialize_Kerberos5GlobalsLib (
	CFragInitBlockPtr	inInitBlock)
{
	OSErr		err = noErr;
	cc_uint32	ccErr;

	/*	Always do this first in your own initialization function -- this calls runtime
		library to initialize your globals and your exceptions table */
	err = __initialize (inInitBlock);
	if (err != noErr)
		return err;
		
	ccErr = cc_initialize (&gCCContext, CC_API_VER_2, NULL, NULL);
	if (ccErr != CC_NOERROR)
		return memFullErr;
		
	gKerberos5GlobalsRefCount++;
	if (gKerberos5SystemDefaultCacheName == nil)
		err = Krb5GlobalsSetUniqueDefaultCacheName ();

	return err;
}

/*	This is the shared library termination function.
	Here you need to undo, in the reverse order, everything you did in 
	the initialization function.
	
	This function can't fail.
*/

pascal void
__terminate_Kerberos5GlobalsLib (
	void)
{
	/*	First, clean up your library-specific structures.
		ErrorLib does nothing here, since it doesn't take ownership
		of error tables */
	
	cc_shutdown (&gCCContext);	
	
	gKerberos5GlobalsRefCount--;

	/*	Dispose ccache name if we are last instance */	
	if ((gKerberos5GlobalsRefCount == 0) && (gKerberos5SystemDefaultCacheName != nil)) {
		DisposePtr (gKerberos5SystemDefaultCacheName);
		gKerberos5SystemDefaultCacheName = nil;
	}
		
	/*	Finally, cleanup exception tables and global chain */
	__terminate ();
}