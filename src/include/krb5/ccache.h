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
#endif /* __KRB5_TCACHE__ */
