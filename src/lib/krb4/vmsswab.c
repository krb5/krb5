/* Copyright 1994 Cygnus Support */
/* Mark W. Eichin */
/*
 * Permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation.
 * Cygnus Support makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/* VMS doesn't have swab, but everything else does */
/* so make this available anyway ... someday it might go
   into the VMS makefile fragment, but for now it is only
   referenced by l.com. */

swab(from,to,nbytes) 
        char *from;
        char *to;
        int nbytes;
{
	char tmp;

        while ( (nbytes-=2) >= 0 ) {
		tmp = from[1];
                to[1] = from[0];
		to[0] = tmp;
                to++; to++;
                from++; from++;
        }
}

