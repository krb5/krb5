/*
 * Copyright 1997 by Massachusetts Institute of Technology
 * 
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose and without fee is
 * hereby granted, provided that the above copyright notice
 * appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation,
 * and that the names of M.I.T. and the M.I.T. S.I.P.B. not be
 * used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * M.I.T. and the M.I.T. S.I.P.B. make no representations about
 * the suitability of this software for any purpose.  It is
 * provided "as is" without express or implied warranty.
 */

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include "com_err.h"
#include "error_table.h"

#if defined(_MSDOS) || defined(_WIN32)
#define HAVE_STRERROR
#endif

#ifdef _MACINTOSH
#define sys_nerr 100
#endif

#if !defined(HAVE_STRERROR) && !defined(SYS_ERRLIST_DECLARED)
extern char const * const sys_errlist[];
extern const int sys_nerr;
#endif

static char buffer[ET_EBUFSIZ];

KRB5_DLLIMP struct et_list KRB5_EXPORTVAR * _et_list = (struct et_list *) NULL;

KRB5_DLLIMP const char FAR * KRB5_CALLCONV et_error_message(ectx, code)
	et_ctx ectx;
	long code;
{
	int offset;
	long l_offset;
	struct et_list *et;
	long table_num;
	int started = 0;
	char *cp;

#if defined(_MSDOS) || defined(_WIN32)
	/*
	 * Winsock defines errors in the range 10000-10100. These are
	 * equivalent to 10000 plus the Berkeley error numbers.
	 *
	 * (Does windows strerror() work right here?)
	 *
	 * XXX NO.  We need to do our own table lookup for Winsock error
	 * messages!!!  --- TYT
	 * 
	 */
	if (code >= 10000 && code <= 10100)	/* Is it Winsock error? */
		code -= 10000;			/* Turn into Berkeley errno */
#endif

	l_offset = code & ((1<<ERRCODE_RANGE)-1);
	offset = (int) l_offset;
	table_num = code - l_offset;
	if (!table_num) {
		if (code == 0)
			goto oops;
	
#ifdef HAVE_STRERROR
		cp = strerror(offset);
		if (cp)
			return cp;
		goto oops;
#else
#ifdef HAVE_SYS_ERRLIST
		if (offset < sys_nerr)
			return(sys_errlist[offset]);
		else
			goto oops;
#else
		goto oops;
#endif /* HAVE_SYS_ERRLIST */
#endif /* HAVE_STRERROR */
	}
	et = ectx ? ectx->tables : _et_list;
	while (et) {
		/* This is to work around a bug in the compiler on the Alpha 
		    comparing longs */
		if (((int) (et->table->base - table_num)) == 0) {
			/* This is the right table */
			if (et->table->n_msgs <= offset)
				break;
			return(et->table->msgs[offset]);
		}
		et = et->next;
	}
oops:
	cp = ectx ? ectx->error_buf : buffer;
	strcpy(cp, "Unknown code ");
	cp += sizeof("Unknown code ") - 1;
	if (table_num) {
		error_table_name_r(table_num, cp);
		while (*cp)
			cp++;
		*cp++ = ' ';
	}
	if (offset >= 100) {
		*cp++ = '0' + offset / 100;
		offset %= 100;
		started++;
	}
	if (started || offset >= 10) {
		*cp++ = '0' + offset / 10;
		offset %= 10;
	}
	*cp++ = '0' + offset;
	*cp = '\0';
	return(buffer);
}

KRB5_DLLIMP const char FAR * KRB5_CALLCONV error_message(code)
	errcode_t	code;
{
	return et_error_message(0, code);
}

