/*
 * lib/krb5/ccache/ccdefops.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Default credentials cache determination.  This is a separate file
 * so that the user can more easily override it.
 */

#include "k5-int.h"

#if defined(macintosh) || defined(_MSDOS) || defined(_WIN32)

/* Macs and PCs use the shared, memory based credentials cache */
#include "stdcc.h" /* from ccapi subdir */

krb5_cc_ops *krb5_cc_dfl_ops = &krb5_cc_stdcc_ops;

#else

#ifdef HAVE_SYS_TYPES_H
/* Systems that have <sys/types.h> probably have Unix-like files (off_t,
   for example, which is needed by fcc.h).  */

#include "fcc.h"		/* From file subdir */
krb5_cc_ops *krb5_cc_dfl_ops = &krb5_cc_file_ops;

#else
/* Systems that don't have <sys/types.h> probably have stdio anyway.  */

#include "scc.h"		/* From stdio subdir */
krb5_cc_ops *krb5_cc_dfl_ops = &krb5_scc_ops;

#endif

#endif
