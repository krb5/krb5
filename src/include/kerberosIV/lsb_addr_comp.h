/*
 * include/kerberosIV/lsb_addr_comp.h
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Comparison macros to emulate LSBFIRST comparison results of network
 * byte-order quantities
 */

#ifndef LSB_ADDR_COMP_DEFS
#define LSB_ADDR_COMP_DEFS

#include "osconf.h"

#ifdef LSBFIRST
#define lsb_net_ulong_less(x,y) ((x < y) ? -1 : ((x > y) ? 1 : 0))
#define lsb_net_ushort_less(x,y) ((x < y) ? -1 : ((x > y) ? 1 : 0))
#else
/* MSBFIRST */
#define u_char_comp(x,y) \
        (((x)>(y))?(1):(((x)==(y))?(0):(-1)))
/* This is gross, but... */
#define lsb_net_ulong_less(x, y) long_less_than((u_char *)&x, (u_char *)&y)
#define lsb_net_ushort_less(x, y) short_less_than((u_char *)&x, (u_char *)&y)

#define long_less_than(x,y) \
        (u_char_comp((x)[3],(y)[3])?u_char_comp((x)[3],(y)[3]): \
	 (u_char_comp((x)[2],(y)[2])?u_char_comp((x)[2],(y)[2]): \
	  (u_char_comp((x)[1],(y)[1])?u_char_comp((x)[1],(y)[1]): \
	   (u_char_comp((x)[0],(y)[0])))))
#define short_less_than(x,y) \
	  (u_char_comp((x)[1],(y)[1])?u_char_comp((x)[1],(y)[1]): \
	   (u_char_comp((x)[0],(y)[0])))

#endif /* LSBFIRST */

#endif /*  LSB_ADDR_COMP_DEFS */
