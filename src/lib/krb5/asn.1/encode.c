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

#ifndef	lint
static char rcsid_encode_c[] =
"$Id$";
#endif	lint

#include <krb5/copyright.h>
#include <isode/psap.h>
#include "KRB5-types.h"
#include <krb5/krb5.h>
#include <errno.h>
#include <krb5/isode_err.h>
#include <krb5/krb5_err.h>
#include <krb5/krb5_tc_err.h>
#include "encode.h"
#include "asn1defs.h"

#include <stdio.h>

#ifdef __STDC__
typedef void * pointer;
#else
typedef char * pointer;
#endif

static char encode_buf[BUFSIZ];

krb5_data *
encode_generic(input, error, encoder, translator, free_translation)
pointer input;
int *error;
int (*encoder)(/* PE, int, int, char *, pointer */);
pointer (*translator)(/* pointer, int * */);
void (*free_translation)(/* pointer  */);
{
    pointer isode_out;
    PE pe;
    PS ps;
    register krb5_data *retval;

    if (!(isode_out = (*translator)(input, error)))
	return(0);
    if (!(ps = ps_alloc(str_open))) {
	*error = ENOMEM;
	free_translation(isode_out);
	return(0);
    }
    if (str_setup(ps, encode_buf, sizeof(encode_buf), 1) != OK) {
	*error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
    errout:
	ps_free(ps);
	free_translation(isode_out);
	return(0);
    }
    if ((*encoder)(&pe, 0, 0, 0, isode_out)) {
	*error = ENOMEM;
	goto errout;
    }
    retval = (krb5_data *)malloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	goto errout;
    }    
    if ((retval->length = ps_get_abs(pe)) > sizeof(encode_buf)) {
	abort();			/* xxx */
    }
    retval->data = malloc(ps_get_abs(pe));
    if (!retval->data) {
	*error = ENOMEM;
	free(retval);
	goto errout;
    }
    if (pe2ps(ps, pe) != OK || ps_flush(ps) != OK) {
	*error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
	free(retval->data);
	free(retval);
	goto errout;
    }
    bcopy(encode_buf, retval->data, retval->length);
    ps_free(ps);
    pe_free(pe);
    free_translation(isode_out);
    return(retval);
}

pointer
decode_generic(input, error, decoder, translator, free_translation)
krb5_data *input;
int *error;
int (*decoder)(/* PE, int, int, char *, pointer */);
pointer (*translator)(/* pointer, int * */);
void (*free_translation)(/* pointer  */);
{
    register pointer krb5_out;
    pointer isode_temp;
    PE pe;
    PS ps;

    if (!(ps = ps_alloc(str_open))) {
	*error = ENOMEM;
	return(0);
    }
    if (str_setup(ps, input->data, input->length, 1) != OK) {
	*error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
	ps_free(ps);
	return(0);
    }
    if (!(pe = ps2pe(ps))) {
	*error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
	ps_free(ps);
	return(0);
    }
    if ((*decoder)(pe, 1, 0, 0, &isode_temp) != OK) {
	*error = ISODE_50_LOCAL_ERR_BADDECODE;
	pe_free(pe);
	ps_free(ps);
	return(0);
    }
    krb5_out = (*translator)(isode_temp, error);
    pe_free(pe);
    ps_free(ps);
    free_translation(isode_temp);
    return(krb5_out);			/* may be error if krb5_out
					   failed above */
}
