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
 
#if defined(macintosh)
#include <CodeFragments.h>

#include "krb5_libinit.h"
#include "crypto_libinit.h"


OSErr __initializeK5(CFragInitBlockPtr ibp);
void __terminateGSSK5glue(void);

OSErr __initializeK5(CFragInitBlockPtr ibp)
{
	OSErr	err = noErr;
	
	err = __initialize();
#else
#define noErr	0
void __initializeK5 (void);
void __initializeK5 (void)
{
        int err = noErr;
#endif
	if (err == noErr) {
		err = krb5int_initialize_library ();
	}
	
	if (err == noErr) {
		err = cryptoint_initialize_library ();
	}
#if defined(macintosh)	
	return err;
#endif
}

#if defined(macintosh)
void __terminateK5(void)
{

	cryptoint_cleanup_library ();
	krb5int_cleanup_library ();

	__terminate();
}
#endif
