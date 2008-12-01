/*
 * kadm_stream.c
 *
 * Copyright 1988, 2002 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * Stream conversion functions for Kerberos administration server
 */

/*
  kadm_stream.c
  this holds the stream support routines for the kerberos administration server

    vals_to_stream: converts a vals struct to a stream for transmission
       internals build_field_header, vts_[string, char, long, short]
    stream_to_vals: converts a stream to a vals struct
       internals check_field_header, stv_[string, char, long, short]
    error: prints out a kadm error message, returns
    fatal: prints out a kadm fatal error message, exits
*/

#include <string.h>
#include <stdlib.h>

#include "kadm.h"
#include "kadm_err.h"
#include "prot.h"

#define min(a,b) (((a) < (b)) ? (a) : (b))

/*
vals_to_stream
  recieves    : kadm_vals *, u_char *
  returns     : a realloced and filled in u_char *

this function creates a byte-stream representation of the kadm_vals structure
*/
int
vals_to_stream(Kadm_vals *dt_in, u_char **dt_out)
{
    int vsloop, stsize;		/* loop counter, stream size */

    stsize = build_field_header(dt_in->fields, dt_out);
    for (vsloop = 31; vsloop >= 0; vsloop--)
	if (IS_FIELD(vsloop, dt_in->fields)) {
	    switch (vsloop) {
	    case KADM_NAME:
		stsize += vts_string(dt_in->name, dt_out, stsize);
		break;
	    case KADM_INST:
		stsize += vts_string(dt_in->instance, dt_out, stsize);
		break;
	    case KADM_EXPDATE:
		stsize += vts_long((KRB_UINT32)dt_in->exp_date,
				   dt_out, stsize);
		break;
	    case KADM_ATTR:
		stsize += vts_short(dt_in->attributes, dt_out, stsize);
		break;
	    case KADM_MAXLIFE:
		stsize += vts_char(dt_in->max_life, dt_out, stsize);
		break;
	    case KADM_DESKEY:
		stsize += vts_long(dt_in->key_high, dt_out, stsize);
		stsize += vts_long(dt_in->key_low, dt_out, stsize);
		break;
	    default:
		break;
	    }
	}
    return stsize;
}

int
build_field_header(
    u_char *cont,		/* container for fields data */
    u_char **st)		/* stream */
{
    *st = malloc(4);
    if (*st == NULL)
	return -1;
    memcpy(*st, cont, 4);
    return 4;	       /* return pointer to current stream location */
}

int
vts_string(char *dat, u_char **st, int loc)
{
    size_t len;
    unsigned char *p;

    if (loc < 0)
	return -1;
    len = strlen(dat) + 1;
    p = realloc(*st, (size_t)loc + len);
    if (p == NULL)
	return -1;
    memcpy(p + loc, dat, len);
    *st = p;
    return len;
}

int
vts_short(KRB_UINT32 dat, u_char **st, int loc)
{
    unsigned char *p;

    if (loc < 0)
	return -1;
    p = realloc(*st, (size_t)loc + 2);
    if (p == NULL)
	return -1;

    *st = p; /* KRB4_PUT32BE will modify p */

    p += loc; /* place bytes at the end */
    KRB4_PUT16BE(p, dat);

    return 2;
}

int
vts_long(KRB_UINT32 dat, u_char **st, int loc)
{
    unsigned char *p;

    if (loc < 0)
	return -1;
    p = realloc(*st, (size_t)loc + 4);
    if (p == NULL)
	return -1;

    *st = p; /* KRB4_PUT32BE will modify p */

    p += loc; /* place bytes at the end */
    KRB4_PUT32BE(p, dat);

    return 4;
}

int
vts_char(KRB_UINT32 dat, u_char **st, int loc)
{
    unsigned char *p;

    if (loc < 0)
	return -1;
    p = realloc(*st, (size_t)loc + 1);
    if (p == NULL)
	return -1;
    p[loc] = dat & 0xff;
    *st = p;
    return 1;
}

/*
stream_to_vals
  recieves    : u_char *, kadm_vals *
  returns     : a kadm_vals filled in according to u_char *

this decodes a byte stream represntation of a vals struct into kadm_vals
*/
int
stream_to_vals(
    u_char *dt_in,
    Kadm_vals *dt_out,
    int maxlen)			/* max length to use */
{
    register int vsloop, stsize; /* loop counter, stream size */
    register int status;

    memset(dt_out, 0, sizeof(*dt_out));

    stsize = check_field_header(dt_in, dt_out->fields, maxlen);
    if (stsize < 0)
	return -1;
    for (vsloop = 31; vsloop >= 0; vsloop--)
	if (IS_FIELD(vsloop, dt_out->fields))
	    switch (vsloop) {
	    case KADM_NAME:
		status = stv_string(dt_in, dt_out->name, stsize,
				    sizeof(dt_out->name), maxlen);
		if (status < 0)
		    return -1;
		stsize += status;
		break;
	    case KADM_INST:
		status = stv_string(dt_in, dt_out->instance, stsize,
				    sizeof(dt_out->instance), maxlen);
		if (status < 0)
		    return -1;
		stsize += status;
		break;
	    case KADM_EXPDATE:
	    {
		KRB_UINT32 exp_date;

		status = stv_long(dt_in, &exp_date, stsize, maxlen);
		if (status < 0)
		    return -1;
		dt_out->exp_date = exp_date;
		stsize += status;
	    }
	    break;
	    case KADM_ATTR:
		status = stv_short(dt_in, &dt_out->attributes, stsize,
				   maxlen);
		if (status < 0)
		    return -1;
		stsize += status;
		break;
	    case KADM_MAXLIFE:
		status = stv_char(dt_in, &dt_out->max_life, stsize,
				  maxlen);
		if (status < 0)
		    return -1;
		stsize += status;
		break;
	    case KADM_DESKEY:
		status = stv_long(dt_in, &dt_out->key_high, stsize,
				  maxlen);
		if (status < 0)
		    return -1;
		stsize += status;
		status = stv_long(dt_in, &dt_out->key_low, stsize,
				  maxlen);
		if (status < 0)
		    return -1;
		stsize += status;
		break;
	    default:
		break;
	    }
    return stsize;
}

int
check_field_header(
    u_char *st,			/* stream */
    u_char *cont,		/* container for fields data */
    int maxlen)
{
    if (4 > maxlen)
	return -1;
    memcpy(cont, st, 4);
    return 4;	       /* return pointer to current stream location */
}

int
stv_string(
    register u_char *st,	/* base pointer to the stream */
    char *dat,			/* a string to read from the stream */
    register int loc,	 /* offset into the stream for current data */
    int stlen,			/* max length of string to copy in */
    int maxlen)			/* max length of input stream */
{
    int maxcount;		/* max count of chars to copy */

    if (loc < 0)
	return -1;
    maxcount = min(maxlen - loc, stlen);
    if (maxcount <= 0)	     /* No strings left in the input stream */
	return -1;

    (void) strncpy(dat, (char *)st + loc, (size_t)maxcount);

    if (dat[maxcount - 1]) /* not null-term --> not enuf room */
	return -1;
    return strlen(dat) + 1;
}

int
stv_short(u_char *st, u_short *dat, int loc, int maxlen)
{
    u_short temp;
    unsigned char *p;

    if (loc < 0 || loc + 2 > maxlen)
	return -1;
    p = st + loc;
    KRB4_GET16BE(temp, p);
    *dat = temp;
    return 2;
}

int
stv_long(u_char *st, KRB_UINT32 *dat, int loc, int maxlen)
{
    KRB_UINT32 temp;
    unsigned char *p;

    if (loc < 0 || loc + 4 > maxlen)
	return -1;
    p = st + loc;
    KRB4_GET32BE(temp, p);
    *dat = temp;
    return 4;
}

int
stv_char(u_char *st, u_char *dat, int loc, int maxlen)
{
    if (loc < 0 || loc + 1 > maxlen)
	return -1;
    *dat = *(st + loc);
    return 1;
}
