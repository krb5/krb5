/*
 * util/et/error_message.c
 *
 * Copyright 1987 by the Student Information Processing Board
 * of the Massachusetts Institute of Technology
 *
 * For copyright info, see "mit-sipb-copyright.h".
 */

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include "com_err.h"
#include "error_table.h"
#include "mit-sipb-copyright.h"
#include "internal.h"

#define sys_nerr 100

static const char copyright[] =
    "Copyright 1986, 1987, 1988 by the Student Information Processing Board\nand the department of Information Systems\nof the Massachusetts Institute of Technology";

static char buffer[25];

struct et_list * _et_list = (struct et_list *) NULL;

const char * INTERFACE error_message (code)
long code;
{
    int offset;
    long l_offset;
    struct et_list *et;
    long table_num;
    int started = 0;
    char *cp;

#ifdef _WINDOWS
/*
** Winsock defines errors in the range 10000-10100. These are equivalent
** to 10000 plus the Berkeley error numbers.
*/
    if (code >= 10000 && code <= 10100)		/* Is it Winsock error? */
	code -= 10000;				/* Turn into Berkeley errno */
#endif

    l_offset = code & ((1<<ERRCODE_RANGE)-1);
    offset = (int) l_offset;
    table_num = code - l_offset;
    if (!table_num) {
#ifdef HAS_SYSERRLIST
#ifdef HAS_STRERROR
	return strerror (offset);
#else
        if (offset < sys_nerr)
	    return(sys_errlist[offset]);
	else
	    goto oops;
#endif
#else
		goto oops;
#endif
    }
    for (et = _et_list; et; et = et->next) {
	if (et->table->base == table_num) {
	    /* This is the right table */
	    if (et->table->n_msgs <= offset)
		goto oops;
	    return(et->table->msgs[offset]);
	}
    }
oops:
    strcpy (buffer, "Unknown code ");
    if (table_num) {
	strcat (buffer, error_table_name (table_num));
	strcat (buffer, " ");
    }
    for (cp = buffer; *cp; cp++)
	;
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
