/*
 * Copyright 1997 by Massachusetts Institute of Technology
 * 
 * Copyright 1986, 1987, 1988 by MIT Student Information Processing Board
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
#include <stdlib.h>
#include "com_err.h"
#include "error_table.h"

#if 0
/*
 * XXX This function is provided without any prototypes in the public
 * interface, and isn't used internally.  It's probably safe to make
 * it go away.
 */
struct foobar {
    struct et_list etl;
    struct error_table et;
};

int init_error_table(msgs, base, count)
    const char * const * msgs;
    int base;
    int count;
{
    struct foobar * new_et;

    if (!base || !count || !msgs)
	return 0;

    new_et = (struct foobar *) malloc(sizeof(struct foobar));
    if (!new_et)
	return errno;	/* oops */
    new_et->etl.table = &new_et->et;
    new_et->et.msgs = msgs;
    new_et->et.base = base;
    new_et->et.n_msgs= count;

    new_et->etl.next = _et_list;
    _et_list = &new_et->etl;
    return 0;
}

extern errcode_t KRB5_CALLCONV et_init(ectx)
	et_ctx *ectx;
{
	struct et_context *ctx;

	ctx = malloc(sizeof(struct et_context));
	if (!ctx)
		return ENOMEM;
	ctx->tables = 0;
	ctx->hook_func = 0;
	ctx->hook_func_data = 0;
	
	*ectx = ctx;
	return 0;
}

extern void KRB5_CALLCONV et_shutdown(ectx)
	et_ctx ectx;	
{
	struct et_list *p, *n;

	p = ectx->tables;
	while (p) {
		n = p->next;
		free(p);
		p = n;
	}
	free(ectx);
}

extern errcode_t KRB5_CALLCONV et_add_error_table(ectx, tbl)
	et_ctx ectx;
	struct error_table *tbl;
{
	struct et_list *e;

	e = malloc(sizeof(struct et_list));
	if (!e)
		return ENOMEM;
	
	e->table = tbl;
	e->next = ectx->tables;
	ectx->tables = e;
	
	return 0;
}

#endif
