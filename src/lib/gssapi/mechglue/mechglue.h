#ident  "@(#)mechglue.h 1.13     95/08/07 SMI"
/*
 * This header contains the mechglue definitions.
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _GSS_MECHGLUE_H
#define _GSS_MECHGLUE_H

#include <gssapi/gssapi.h>
#include <sys/types.h>

/********************************************************/
/* GSSAPI Extension functions -- these functions aren't */
/* in the GSSAPI, but they are provided in this library */

int gssd_pname_to_uid (char *, gss_OID, gss_OID, uid_t *);
void gss_initialize (void);

#endif /* _GSS_MECHGLUE_H */
