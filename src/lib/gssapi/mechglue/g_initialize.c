#ident	"@(#)gss_initialize.c	1.5	95/09/11 SMI"
/*
 * This function will initialize the gssapi mechglue library
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

extern gss_mechanism krb5_gss_initialize();

static int _gss_initialized = 0;

void gss_initialize (void)
{
    gss_mechanism mech;

    /* Make sure we've not run already */
    if (_gss_initialized)
	return;
    _gss_initialized = 1;

    /* 
     * Use hard-coded in mechanisms...  I need to know what mechanisms
     * are supported...  As more mechanisms become supported, they
     * should be added here, unless shared libraries are used.
     */

    /* Initialize the krb5 mechanism */
    mech = (gss_mechanism)krb5_gss_initialize();
    if (mech)
	add_mechanism (mech, 1);

    return;
}
