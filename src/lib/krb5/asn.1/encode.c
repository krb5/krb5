/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 *
 * encoding glue routines.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_encode_c[] =
"$Id$";
#endif	/* lint || saber */

#include <isode/psap.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

#include <stdio.h>

krb5_error_code
krb5_encode_generic(input, data_out, encoder, translator, free_translation)
krb5_const_pointer input;
register krb5_data **data_out;
int (*encoder) PROTOTYPE((PE *, int, int, char *, krb5_pointer));
krb5_pointer (*translator) PROTOTYPE((krb5_const_pointer, int * ));
void (*free_translation) PROTOTYPE((krb5_pointer ));
{
    krb5_pointer isode_out;
    PE pe;
    PS ps;
    krb5_error_code error;

    ps_len_strategy = PS_LEN_LONG;	/* force use of definite form */

    if (!(isode_out = (*translator)(input, &error)))
	return(error);
    if ((*encoder)(&pe, 0, 0, 0, isode_out)) {
	error = ENOMEM;
	goto errout;
    }
    *data_out = (krb5_data *)malloc(sizeof(**data_out));
    if (!*data_out) {
	error = ENOMEM;
	goto peout;
    }    
    (*data_out)->length = ps_get_abs(pe);
    (*data_out)->data = malloc((*data_out)->length);
    if (!(*data_out)->data) {
	error = ENOMEM;
	goto datout;
    }
    if (!(ps = ps_alloc(str_open))) {
	error = ENOMEM;
	goto alldatout;
    }
    if (str_setup(ps, (*data_out)->data, (*data_out)->length, 1) != OK) {
	error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
	goto oops;
    }
    if (pe2ps(ps, pe) != OK || ps_flush(ps) != OK) {
	error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
    oops:
	ps_free(ps);
    alldatout:
	free((*data_out)->data);
    datout:
	xfree(*data_out);
	*data_out = 0;
    peout:
	pe_free(pe);
    errout:
	(*free_translation)(isode_out);
	return(error);
    }
    ps_free(ps);
    pe_free(pe);
    (*free_translation)(isode_out);
    return(0);
}
