/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * decoding glue routines.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_decode_c[] =
"$Id$";
#endif	/* lint || saber */

#include <isode/psap.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

#include <stdio.h>

krb5_error_code
krb5_decode_generic(input, output, decoder, translator, free_translation)
const krb5_data *input;
register krb5_pointer *output;
decoder_func decoder;
translator_func translator;
free_func free_translation;
{
    krb5_pointer isode_temp;
    PE pe;
    PS ps;
    krb5_error_code error = 0;

    if (!(ps = ps_alloc(str_open))) {
	return(ENOMEM);
    }
    if (str_setup(ps, input->data, input->length, 1) != OK) {
	error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
	ps_free(ps);
	return(error);
    }
    if (!(pe = ps2pe(ps))) {
	error = ps->ps_errno + ISODE_50_PS_ERR_NONE;
	ps_free(ps);
	return(error);
    }
    if ((*decoder)(pe, 1, 0, 0, &isode_temp) != OK) {
	error = ISODE_50_LOCAL_ERR_BADDECODE;
	pe_free(pe);
	ps_free(ps);
	return(error);
    }
    *output = (*translator)(isode_temp, &error);
    pe_free(pe);
    ps_free(ps);
    (*free_translation)(isode_temp);
    return(error);			/* may be error if output
					   failed above */
}
