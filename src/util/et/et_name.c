/*
 * Copyright 1997 by Massachusetts Institute of Technology
 * 
 * Copyright 1987 by MIT Student Information Processing Board
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

#include "com_err.h"
#include "error_table.h"

static const char char_set[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

const char * error_table_name_r(num, out)
	unsigned long num;
	char FAR *out;
{
	long ch;
	int i;
	char *p;

	p = out;
	num >>= ERRCODE_RANGE;

	for (i = 3; i >= 0; i--) {
		ch = (num >> BITS_PER_CHAR * i) & ((1 << BITS_PER_CHAR) - 1);
		if (ch != 0)
			*p++ = char_set[ch-1];
	}
	*p = '\0';
	return(out);
}

const char FAR * error_table_name(num)
	unsigned long num;
{
	static char buf[6];

	return error_table_name_r(num, buf);
}
