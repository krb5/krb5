/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Definitions for this implementation of the libos layer.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_LIBOS__
#define __KRB5_LIBOS__

/* lock mode flags */
#define	KRB5_LOCKMODE_SHARED	0x0001
#define	KRB5_LOCKMODE_EXCLUSIVE	0x0002
#define	KRB5_LOCKMODE_DONTBLOCK	0x0004
#define	KRB5_LOCKMODE_UNLOCK	0x0008

/* get all the addresses of this host */
extern int krb5_os_localaddr PROTOTYPE((krb5_address ***addr));

#endif /* __KRB5_LIBOS__ */
