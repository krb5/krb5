/*
 * Copyright 1997,2000,2001 by Massachusetts Institute of Technology
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

#if defined(_WIN32)
#define HAVE_STRERROR
#endif

#if !defined(HAVE_STRERROR) && !defined(SYS_ERRLIST_DECLARED)
extern char const * const sys_errlist[];
extern const int sys_nerr;
#endif

static char buffer[ET_EBUFSIZ];

#if (defined(_WIN32) || TARGET_OS_MAC)
/*@null@*/ static struct et_list * _et_list = (struct et_list *) NULL;
#else
/* Old interface compatibility */
/*@null@*/ struct et_list * _et_list = (struct et_list *) NULL;
#endif

/*@null@*//*@only@*/static struct dynamic_et_list * et_list_dynamic;

#ifndef DEBUG_TABLE_LIST
#define dprintf(X)
#else
#define dprintf(X) printf X
#endif

const char * KRB5_CALLCONV
error_message(long code)
    /*@modifies internalState@*/
{
	unsigned long offset;
	unsigned long l_offset;
	struct et_list *et;
	struct dynamic_et_list *det;
	unsigned long table_num;
	int started = 0;
	unsigned int divisor = 100;
	char *cp;
	const struct error_table *table;

	l_offset = (unsigned long)code & ((1<<ERRCODE_RANGE)-1);
	offset = l_offset;
	table_num = ((unsigned long)code - l_offset) & ERRCODE_MAX;
	if (table_num == 0) {
#ifdef __sgi
	system_error_code:
#endif
		if (code == 0)
			goto oops;

		/* This could trip if int is 16 bits.  */
		if ((unsigned long)(int)code != code)
		    abort ();
#ifdef HAVE_STRERROR
		cp = strerror((int) code);
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
#ifdef __sgi
	/* Irix 6.5 uses a much bigger table than other UNIX systems
	   I've looked at, but the table is sparse.  The sparse
	   entries start around 500, but sys_nerr is only 152.  */
	if (code > 0 && code <= 1600)
	    goto system_error_code;
#endif

	dprintf (("scanning static list for %x\n", table_num));
	for (et = _et_list; et != NULL; et = et->next) {
	    if (et->table == NULL)
		continue;
	    dprintf (("\t%x = %s\n", et->table->base & ERRCODE_MAX,
		      et->table->msgs[0]));
	    if ((et->table->base & ERRCODE_MAX) == table_num) {
		table = et->table;
		goto found;
	    }
	}
	dprintf (("scanning dynamic list for %x\n", table_num));
	for (det = et_list_dynamic; det != NULL; det = det->next) {
	    dprintf (("\t%x = %s\n", det->table->base & ERRCODE_MAX,
		      det->table->msgs[0]));
	    if ((det->table->base & ERRCODE_MAX) == table_num) {
		table = det->table;
		goto found;
	    }
	}
	goto no_table_found;

 found:
	dprintf (("found it!\n"));
	/* This is the right table */

	/* This could trip if int is 16 bits.  */
	if ((unsigned long)(unsigned int)offset != offset)
	    goto no_table_found;

	if (table->n_msgs <= (unsigned int) offset)
	    goto no_table_found;

	return table->msgs[offset];

 no_table_found:
#if defined(_WIN32)
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

#if TARGET_OS_MAC
	{
		/* ComErr doesn't know about this error, ask the system */
		/* Of course there's no way to tell if it knew what error it got */
		return (strerror (code));
	}
#endif
	
	cp = buffer;
	strcpy(cp, "Unknown code ");
	cp += sizeof("Unknown code ") - 1;
	if (table_num != 0L) {
		(void) error_table_name_r(table_num, cp);
		while (*cp != '\0')
			cp++;
		*cp++ = ' ';
	}
	while (divisor > 1) {
	    if (started != 0 || offset >= divisor) {
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

/*@-incondefs@*/ /* _et_list is global on unix but not in header annotations */
errcode_t KRB5_CALLCONV
add_error_table(/*@dependent@*/ const struct error_table * et)
     /*@modifies _et_list,et_list_dynamic@*/
/*@=incondefs@*/
{
    struct dynamic_et_list *del;

    del = (struct dynamic_et_list *)malloc(sizeof(struct dynamic_et_list));
    if (del == NULL)
	return errno;

    del->table = et;
    del->next = et_list_dynamic;
    et_list_dynamic = del;
    return 0;
}

/*@-incondefs@*/ /* _et_list is global on unix but not in header annotations */
errcode_t KRB5_CALLCONV
remove_error_table(const struct error_table * et)
     /*@modifies _et_list,et_list_dynamic@*/
/*@=incondefs@*/
{
    struct dynamic_et_list **del;
    struct et_list **el;

    /* Remove the first occurrance we can find.  Prefer dynamic
       entries, but if there are none, check for a static one too.  */
    for (del = &et_list_dynamic; *del; del = &(*del)->next)
	if ((*del)->table->base == et->base) {
	    /*@only@*/ struct dynamic_et_list *old = *del;
	    *del = old->next;
	    free (old);
	    return 0;
	}
    for (el = &_et_list; *el; el = &(*el)->next)
	if ((*el)->table != NULL && (*el)->table->base == et->base) {
	    struct et_list *old = *el;
	    *el = old->next;
	    old->next = NULL;
	    old->table = NULL;
	    return 0;
	}
    return ENOENT;
}
