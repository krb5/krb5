/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * encoding glue routines.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_encode_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <isode/psap.h>
#include "KRB5-types.h"
#include <krb5/krb5.h>
#include <errno.h>
#include <krb5/isode_err.h>
#include <krb5/krb5_err.h>
#include "encode.h"
#include "asn1defs.h"

#include <krb5/ext-proto.h>

#include <stdio.h>

krb5_error_code
encode_generic(input, data_out, encoder, translator, free_translation)
const krb5_pointer input;
register krb5_data **data_out;
int (*encoder) PROTOTYPE((PE *, int, int, char *, krb5_pointer));
krb5_pointer (*translator) PROTOTYPE((krb5_pointer, int * ));
void (*free_translation) PROTOTYPE((krb5_pointer ));
{
    krb5_pointer isode_out;
    PE pe;
    PS ps;
    char encode_buf[BUFSIZ];
    krb5_error_code error;

    if (!(isode_out = (*translator)(input, &error)))
	return(error);
    if (!(ps = ps_alloc(str_open))) {
	free_translation(isode_out);
	return(ENOMEM);
    }
    if (str_setup(ps, encode_buf, sizeof(encode_buf), 1) != OK) {
	error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
    errout:
	ps_free(ps);
	free_translation(isode_out);
	return(error);
    }
    if ((*encoder)(&pe, 0, 0, 0, isode_out)) {
	error = ENOMEM;
	goto errout;
    }
    *data_out = (krb5_data *)malloc(sizeof(**data_out));
    if (!*data_out) {
	error = ENOMEM;
	goto errout;
    }    
    if (((*data_out)->length = ps_get_abs(pe)) > sizeof(encode_buf)) {
	abort();			/* xxx */
    }
    (*data_out)->data = malloc(ps_get_abs(pe));
    if (!(*data_out)->data) {
	error = ENOMEM;
	free((char *)*data_out);
	*data_out = 0;
	goto errout;
    }
    if (pe2ps(ps, pe) != OK || ps_flush(ps) != OK) {
	error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
	free((*data_out)->data);
	free((char *)*data_out);
	*data_out = 0;
	goto errout;
    }
    bcopy(encode_buf, (*data_out)->data, (*data_out)->length);
    ps_free(ps);
    pe_free(pe);
    free_translation(isode_out);
    return(0);
}
