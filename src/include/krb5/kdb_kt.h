/*
 * include/krb5/kdb_kt.h
 *
 * Copyright 1997 by the Massachusetts Institute of Technology.
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
 * KDC keytab definitions.
 */


#ifndef KRB5_KDB5_KT_H
#define KRB5_KDB5_KT_H

#if !defined(macintosh) && !defined(_MSDOS)

#include "kdb.h"

krb5_error_code krb5_ktkdb_resolve
        KRB5_PROTOTYPE((krb5_context, krb5_keytab *));

#endif /* !defined(macintosh) && !defined(_MSDOS) */
#endif /* KRB5_KDB5_DBM__ */
