/*
 * Copyright 1988 by the Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#ifndef _ET_H

#include <errno.h>

#define ET_EBUFSIZ 32

struct et_context {
	struct et_list		FAR *tables;
	et_error_hook_func	hook_func;
	void			FAR *hook_func_data;
	char			error_buf[ET_EBUFSIZ];
};

struct et_list {
    struct et_list FAR *next;
    const struct error_table FAR *table;
};

extern struct et_list FAR * _et_list;

#define	ERRCODE_RANGE	8	/* # of bits to shift table number */
#define	BITS_PER_CHAR	6	/* # bits to shift per character in name */

extern const char FAR *error_table_name ET_P((long));
extern const char FAR *error_table_name_r ET_P((long, char FAR *));

#define _ET_H
#endif
