/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * encoding glue routines.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_encode_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <isode/psap.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>

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
	free((char *)*data_out);
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
