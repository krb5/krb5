/*
 * Copyright 1988 by the Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#ifndef _ET_H

#include <errno.h>

#define ET_EBUFSIZ 64

struct et_list {
    /*@dependent@*//*@null@*/ struct et_list *next;
    /*@dependent@*//*@null@*/ const struct error_table *table;
};
#if !defined(_WIN32)
/*@null@*//*@dependent@*/ extern struct et_list * _et_list;
#endif

struct dynamic_et_list {
    /*@only@*//*@null@*/ struct dynamic_et_list *next;
    /*@dependent@*/ const struct error_table *table;
};

#define	ERRCODE_RANGE	8	/* # of bits to shift table number */
#define	BITS_PER_CHAR	6	/* # bits to shift per character in name */
#define ERRCODE_MAX   0xFFFFFFFFUL      /* Mask for maximum error table */

extern /*@observer@*/ const char *error_table_name (unsigned long)
     /*@modifies internalState@*/;
extern const char *error_table_name_r (unsigned long,
					   /*@out@*/ /*@returned@*/ char *outbuf)
     /*@modifies outbuf@*/;

#define _ET_H
#endif
