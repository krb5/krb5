/*
 * $Source$
 * $Author$
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Miscellaneous debug printing utilities
 */

#ifndef	lint
static char rcsid_util_c[] =
"$Header$";
#endif	/* lint */

#include <stdio.h>

/* Application include files */
#include "k5-int.h"
#include "des.h"

void des_cblock_print_file(x, fp)
    des_cblock *x;
    FILE *fp;
{
    unsigned char *y = (unsigned char *) x;
    register int i = 0;
    fprintf(fp," 0x { ");

    while (i++ < 8) {
	fprintf(fp,"%x",*y++);
	if (i < 8)
	    fprintf(fp,", ");
    }
    fprintf(fp," }");
}
