/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * definitions for free routines
 */


#ifndef KRB5_FREE__
#define KRB5_FREE__

/* to keep lint happy */
#define xfree(val) free((char *)(val))

#define krb5_free_data(val) { xfree((val)->data); xfree(val);}

#endif /* KRB5_FREE__ */
