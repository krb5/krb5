/*
 *   Copyright (C) 1997 by the Massachusetts Institute of Technology
 *   All rights reserved.
 *
 *   For copying and distribution information, please see the file
 *   COPYRIGHT.
 */
 
 
#include <CodeFragments.h>
 
#include "gssapi_err_generic.h"
#include "gssapi_err_krb5.h"


OSErr __initializeGSS(CFragInitBlockPtr ibp);
void __terminateGSS(void);

OSErr __initializeGSS(CFragInitBlockPtr ibp)
{
	OSErr	err = noErr;
	
	/* Do normal init of the shared library */
	err = __initialize();
	
	/* Initialize the error tables */
	if (err == noErr) {
	    add_error_table(&et_k5g_error_table);
	    add_error_table(&et_ggss_error_table);
	}
	
	return err;
}

void __terminateGSS(void)
{

	OM_uint32 maj_stat, min_stat;

	maj_stat = kg_release_defcred (&min_stat);
	
    remove_error_table(&et_k5g_error_table);
    remove_error_table(&et_ggss_error_table);

	__terminate();
}
