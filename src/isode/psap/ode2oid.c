/* ode2oid.c - object descriptor to object identifier */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:32:56  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:23  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:51  isode
 * Release 7.0
 * 
 * 
 */

/*
 *				  NOTICE
 *
 *    Acquisition, use, and distribution of this module and related
 *    materials are subject to the restrictions of a license agreement.
 *    Consult the Preface in the User's Manual for the full terms of
 *    this agreement.
 *
 */


/* LINTLIBRARY */

#include <stdio.h>
#include "psap.h"
#include "ppkt.h"

/* work around define collisions */
#undef missingP
#undef pylose
#include "rtpkt.h"

/* work around type clashes */
#undef missingP
#undef pylose
#undef toomuchP
#define ACSE
#define assocblk assocblkxxx
#define newacblk newacblkxxx
#define findacblk findacblkxxx
#include "acpkt.h"

/*  */
#define ODECACHESIZE 10
static struct la_cache {
	char	*descriptor;	
	int	ref;
	OID	oid;
} Cache[ODECACHESIZE];

static void preloadcache (str)
char	*str;
{
    struct la_cache *cp = &Cache[0];
    register struct isobject *io;

    (void) setisobject (0);
    while (io = getisobject ()) {
	if (strcmp (str, io -> io_descriptor) == 0 ||
	    strcmp (DFLT_ASN, io -> io_descriptor) == 0 ||
	    strcmp (AC_ASN, io -> io_descriptor) == 0 ||
	    strcmp (BER, io -> io_descriptor) == 0 ||
	    strcmp (RT_ASN, io -> io_descriptor) == 0) {
	    if ((cp -> oid = oid_cpy (&io -> io_identity)) == NULLOID ||
		(cp -> descriptor = malloc ((unsigned) (strlen (io -> io_descriptor) + 1)))
		== NULLCP) {
		if (cp -> oid) {
		    oid_free (cp -> oid);
		    cp -> oid = NULLOID;
		}
	    }
	    else {
		(void) strcpy (cp -> descriptor, io -> io_descriptor);
		cp -> ref = 1;
		cp ++;
	    }
	}
    }
    (void) endisobject ();
}

OID	ode2oid (descriptor)
char   *descriptor;
{
    register struct isobject *io;
    int i, least;
    struct la_cache *cp, *cpn;
    static char firsttime = 0;

    if (firsttime == 0) {
	preloadcache (descriptor);
	firsttime = 1;
    }

    least = Cache[0].ref;
    for (cpn = cp = &Cache[0], i = 0; i < ODECACHESIZE; i++, cp++) {
	if (cp -> ref < least) {
	    least = cp -> ref;
	    cpn = cp;
	}
	if (cp -> ref <= 0)
		continue;
	if (strcmp (descriptor, cp -> descriptor) == 0) {
	    cp -> ref ++;
	    return cp -> oid;
	}
    }

    if ((io = getisobjectbyname (descriptor)) == NULL)
	return NULLOID;

    if (cpn -> oid)
	    oid_free (cpn -> oid);
    if (cpn -> descriptor)
	    free (cpn -> descriptor);

    cpn -> ref = 1;
    if ((cpn -> oid = oid_cpy (&io -> io_identity)) == NULLOID ||
	(cpn -> descriptor = malloc ((unsigned) (strlen (descriptor) + 1))) == NULLCP) {
	if (cpn -> oid) {
	    oid_free (cpn -> oid);
	    cpn -> oid = NULLOID;
	}
        cpn -> ref = 0;
    }
    else
	(void) strcpy (cpn -> descriptor, descriptor);

    return (&io -> io_identity);
}
