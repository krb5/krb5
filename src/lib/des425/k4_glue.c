/*
 * lib/des425/k4_glue.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * k4_glue.c	- The glue which holds us together with old versions of K4.
 */

/*
 * This is here because old versions of the Kerberos version 4 library
 * reference this symbol.  It's just a dangling reference which is supposed
 * to be defined by referencing modules.  For the purpose of building shared
 * libraries, we'll need a definition, and since the des425 library is
 * required for K4 compatability, this is as good a place as any.
 *
 * In an effort to keep this bit of (ahem) logic from being too intrusive,
 * we use #pragma weak, if available, otherwise just go with a normal def.
 */

#if	HAVE_PRAGMA_WEAK
#pragma weak req_act_vno = des425_req_act_vno
const int des425_req_act_vno = 4;
#else	/* HAVE_PRAGMA_WEAK */
const int req_act_vno = 4;
#endif	/* HAVE_PRAGMA_WEAK */
