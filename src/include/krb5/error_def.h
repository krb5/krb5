/*
 * $Source$
 * $Author$
 * $Id$
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
 * Error code definitions.
 */


#ifndef KRB5_ERROR_DEF__
#define KRB5_ERROR_DEF__

#include <krb5/krb5_err.h>
#include <krb5/kdb5_err.h>
#ifndef KRB5_USE_ISODE
#include <krb5/asn1_err.h>
#else
#include <krb5/isode_err.h>
#endif
#include <errno.h>

#endif /* KRB5_ERROR_DEF__ */
