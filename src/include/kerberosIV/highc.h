/*
 * include/kerberosIV/highc.h
 *
 * Copyright 1988, 1994 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * Known breakage in the version of Metaware's High C compiler that
 * we've got available....
 */

#define const
/*#define volatile*/

/*
 * Some builtin functions we can take advantage of for inlining....
 */

#define abs			_abs
/* the _max and _min builtins accept any number of arguments */
#undef MAX
#define MAX(x,y)		_max(x,y)
#undef MIN
#define MIN(x,y)		_min(x,y)
/*
 * I'm not sure if 65535 is a limit for this builtin, but it's
 * reasonable for a string length.  Or is it?
 */
/*#define strlen(s)		_find_char(s,65535,0)*/
#define bzero(ptr,len)		_fill_char(ptr,len,'\0')
#define bcmp(b1,b2,len)		_compare(b1,b2,len)
