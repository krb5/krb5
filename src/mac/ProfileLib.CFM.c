/*
 *   Copyright (C) 1997 by the Massachusetts Institute of Technology
 *   All rights reserved.
 *
 *   For copying and distribution information, please see the file
 *   COPYRIGHT.
 */
 
 
#include <CodeFragments.h>

#include "profile.h"


OSErr InitializeProfileLib (
	CFragInitBlockPtr ibp);
void TerminateProfileLib (void);

OSErr InitializeProfileLib(
	CFragInitBlockPtr ibp)
{
	OSErr	err = noErr;
	
	/* Do normal init of the shared library */
	err = __initialize(ibp);
	
	/* Initialize the error tables */
	if (err == noErr) {
	    add_error_table(&et_prof_error_table);
	}
	
	return err;
}

void TerminateProfileLib(void)
{
    remove_error_table(&et_prof_error_table);
	__terminate();
}
