
/*
 * The routine parsetos() for UNICOS 6.0/6.1, as well as more traditional
 * Unix systems.  This is part of UNICOS 7.0 and later.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#define NEED_PARSETOS
#include "misc-proto.h"

#define	MIN_TOS	0
#define	MAX_TOS	255

int
parsetos(name, proto)
char	*name;
char	*proto;
{
#if 0
	register char	*c;
#endif
	int		tos;

#ifdef HAVE_GETTOSBYNAME
	struct tosent	*tosp;

	tosp = gettosbyname(name, proto);
	if (tosp)
		tos = tosp->t_tos;
	else
#endif
		tos = (int)strtol(name, (char **)NULL, 0);

	if (tos < MIN_TOS || tos > MAX_TOS) {
		return (-1);
	}
	return (tos);
}
