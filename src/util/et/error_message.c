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
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
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

#ifdef macintosh
#include <ErrorLib.h>
#endif

#if defined(_MSDOS) || defined(_WIN32)
#define HAVE_STRERROR
#endif

#ifdef macintosh
#define sys_nerr 100   /* XXX - What is this? */
#endif

#if !defined(HAVE_STRERROR) && !defined(SYS_ERRLIST_DECLARED)
extern char const * const sys_errlist[];
#ifndef macintosh
extern const int sys_nerr;
#endif
#endif

static char buffer[ET_EBUFSIZ];

#if (defined(_MSDOS) || defined(_WIN32) || defined(macintosh))
static struct et_list * _et_list = (struct et_list *) NULL;
#else
/* Old interface compatibility */
struct et_list * _et_list = (struct et_list *) NULL;
#endif

KRB5_DLLIMP const char FAR * KRB5_CALLCONV error_message(code)
	long code;
{
	unsigned long offset;
	unsigned long l_offset;
	struct et_list *et;
	unsigned long table_num;
	int started = 0;
	unsigned int divisor = 100;
	char *cp;

	l_offset = (unsigned long)code & ((1<<ERRCODE_RANGE)-1);
	offset = l_offset;
	table_num = ((unsigned long)code - l_offset) & ERRCODE_MAX;
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

	et = _et_list;
	while (et) {
	    if ((et->table->base & ERRCODE_MAX) == table_num) {
			/* This is the right table */
			if (et->table->n_msgs <= offset)
				break;
			return(et->table->msgs[offset]);
		}
		et = et->next;
	}

#if defined(_MSDOS) || defined(_WIN32)
	/*
	 * WinSock errors exist in the 10000 and 11000 ranges
	 * but might not appear if WinSock is not initialized
	 */
	if (code < 12000) {
		table_num = 0;
		offset = code;
		divisor = 10000;
	}
#endif
#ifdef _WIN32	
	{
		LPVOID msgbuf;

		if (! FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
				     NULL /* lpSource */,
				     (DWORD) code,
				     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				     (LPTSTR) &msgbuf,
				     (DWORD) 0 /*sizeof(buffer)*/,
				     NULL /* va_list */ )) {
			/*
			 * WinSock errors exist in the 10000 and 11000 ranges
			 * but might not appear if WinSock is not initialized
			 */
			if (code < 12000) {
			    table_num = 0;
			    offset = code;
			    divisor = 10000;
			}

			goto oops;
		} else {
			strncpy(buffer, msgbuf, sizeof(buffer));
			buffer[sizeof(buffer)-1] = '\0';
			cp = buffer + strlen(buffer) - 1;
			if (*cp == '\n') *cp-- = '\0';
			if (*cp == '\r') *cp-- = '\0';
			if (*cp == '.') *cp-- = '\0';

			LocalFree(msgbuf);
			return buffer;
		}
	}
#endif

oops:

#if defined(macintosh)
	{
		/* This may be a Mac OS Toolbox error or an MIT Support Library Error.  Ask ErrorLib */
		if (GetErrorLongString(code, buffer, ET_EBUFSIZ - 1) == noErr) {
			return buffer;
		}
	}
#endif
	
	cp = buffer;
	strcpy(cp, "Unknown code ");
	cp += sizeof("Unknown code ") - 1;
	if (table_num) {
		error_table_name_r(table_num, cp);
		while (*cp)
			cp++;
		*cp++ = ' ';
	}
	while (divisor > 1) {
	    if (started || offset >= divisor) {
		*cp++ = '0' + offset / divisor;
		offset %= divisor;
		started++;
	    }
	    divisor /= 10;
	}
	*cp++ = '0' + offset;
	*cp = '\0';
	return(buffer);
}


#ifdef _MSDOS
/*
 * Win16 applications cannot call malloc while the DLL is being
 * initialized...  To get around this, we pre-allocate an array
 * sufficient to hold several error tables.
 */
#define PREALLOCATE_ETL 32
static struct et_list etl[PREALLOCATE_ETL];
static int etl_used = 0;
#endif

KRB5_DLLIMP errcode_t KRB5_CALLCONV
add_error_table(et)
    const struct error_table FAR * et;
{
    struct et_list *el = _et_list;

    while (el) {
	if (el->table->base == et->base)
	    return EEXIST;
	el = el->next;
    }

#ifdef _MSDOS
    if (etl_used < PREALLOCATE_ETL)
	el = &etl[etl_used++];
    else
#endif
	if (!(el = (struct et_list *)malloc(sizeof(struct et_list))))
	    return ENOMEM;

    el->table = et;
    el->next = _et_list;
    _et_list = el;

    return 0;
}

KRB5_DLLIMP errcode_t KRB5_CALLCONV
remove_error_table(et)
    const struct error_table FAR * et;
{
    struct et_list *el = _et_list;
    struct et_list *el2 = 0;

    while (el) {
	if (el->table->base == et->base) {
	    if (el2)	/* Not the beginning of the list */
		el2->next = el->next;
	    else
		_et_list = el->next;
#ifdef _MSDOS
	    if ((el < etl) || (el > &etl[PREALLOCATE_ETL-1]))
#endif
		(void) free(el);
	    return 0;
	}
	el2 = el;
	el = el->next;
    }
    return ENOENT;
}
