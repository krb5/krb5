/*
 *   Copyright (C) 1997 by the Massachusetts Institute of Technology
 *   All rights reserved.
 *
 *   For copying and distribution information, please see the file
 *   COPYRIGHT.
 */
 
 
#include <CodeFragments.h>

#include "krb5_err.h"
#include "kv5m_err.h"
#include "asn1_err.h"
#include "kdb5_err.h"
#include "profile.h"
#include "adm_err.h"


OSErr __initializeK5(CFragInitBlockPtr ibp);
void __terminateGSSK5glue(void);

OSErr __initializeK5(CFragInitBlockPtr ibp)
{
	OSErr	err = noErr;
	
	/* Do normal init of the shared library */
	err = __initialize();
	
	/* Initialize the error tables */
	if (err == noErr) {
	    add_error_table(&et_krb5_error_table);
	    add_error_table(&et_kv5m_error_table);
	    add_error_table(&et_kdb5_error_table);
	    add_error_table(&et_asn1_error_table);
//	    add_error_table(&et_prof_error_table);
	    add_error_table(&et_kadm_error_table);
	}
	
	return err;
}

void __terminateK5(void)
{

	krb5_stdcc_shutdown();
	
    remove_error_table(&et_krb5_error_table);
    remove_error_table(&et_kv5m_error_table);
    remove_error_table(&et_kdb5_error_table);
    remove_error_table(&et_asn1_error_table);
//    remove_error_table(&et_prof_error_table);
    remove_error_table(&et_kadm_error_table);

	__terminate();
}
