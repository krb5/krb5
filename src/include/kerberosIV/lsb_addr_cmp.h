/*
 * include/kerberosIV/lsb_addr_cmp.h
 *
 * Copyright 1988, 1995 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Comparison macros to emulate LSBFIRST comparison results of network
 * byte-order quantities
 */

#include "mit-copyright.h"
#ifndef LSB_ADDR_COMP_DEFS
#define LSB_ADDR_COMP_DEFS

/* #include "osconf.h" */

/* note that if we don't explicitly know if we're LSBFIRST, the 
   alternate code is byte order independent and will give the
   right answer. */
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

/* For krb4 library internal use only.  */
extern int krb4int_address_less (struct sockaddr_in *, struct sockaddr_in *);

#endif /*  LSB_ADDR_COMP_DEFS */
