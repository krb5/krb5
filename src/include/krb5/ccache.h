/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Ticket cache definitions.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_TCACHE__
#define __KRB5_TCACHE__

typedef char *	krb5_tcache_name;	/* a name of a ticket cache */
typedef	int	krb5_tcache_id;		/* a short "identifier" for quick
					   cache access */
typedef	int	krb5_tcache_magic;	/* cookie for sequential lookup */

#define	KRB5_TC_READ	0		/* open cache for read only */
#define	KRB5_TC_RDWR	1		/* open cache for read/write */

/* for retrieve_cred */
#define	KRB5_TC_MATCH_TIMES		0x00000001
#define	KRB5_TC_MATCH_IS_SKEY		0x00000002
#define	KRB5_TC_MATCH_FLAGS		0x00000004
#define	KRB5_TC_MATCH_TIMES_EXACT	0x00000008
#define	KRB5_TC_MATCH_FLAGS_EXACT	0x00000010

#endif /* __KRB5_TCACHE__ */
