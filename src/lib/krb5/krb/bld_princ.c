/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * Build a principal from a list of strings
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_bld_princ_c [] =
"$Id$";
#endif	/* !lint & !SABER */

/* Need <krb5/config.h> for STDARG_PROTOTYPES */
#include <krb5/krb5.h>

#if __STDC__ || defined(STDARG_PROTOTYPES)
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include <krb5/ext-proto.h>

krb5_error_code
krb5_build_principal_va(princ, rlen, realm, ap)
krb5_principal *princ;
int rlen;
const char *realm;
va_list ap;
{
    register int i, count = 0;
    register char *next;
    krb5_principal princ_ret;

    /* guess at an initial sufficent count of 2 pieces */
    count = 2 + 2;		/* plus 2 for realm & null terminator */

    /* get space for array and realm, and insert realm */
    princ_ret = (krb5_principal) malloc(sizeof(*princ_ret) * (count));
    if (!princ_ret)
	return ENOMEM;
    if (!(princ_ret[0] = (krb5_data *) malloc(sizeof(*princ_ret[0])))) {
	xfree(princ_ret);
	return ENOMEM;
    }
    princ_ret[0]->length = rlen;
    princ_ret[0]->data = malloc(rlen);
    if (!princ_ret[0]->data) {
	xfree(princ_ret[0]);
	xfree(princ_ret);
	return ENOMEM;
    }
    memcpy(princ_ret[0]->data, realm, rlen);

    /* process rest of components */

    for (i = 1, next = va_arg(ap, char *);
	 next;
	 next = va_arg(ap, char *), i++) {
	if (i == count-1) {
	    /* not big enough.  realloc the array */
	    krb5_principal p_tmp;
	    p_tmp = (krb5_principal) realloc((char *)princ_ret, sizeof(*princ_ret)*(count*2));
	    if (!p_tmp)
		goto free_out;
	    princ_ret = p_tmp;
	    count *= 2;
	}
	if (!(princ_ret[i] =
	      (krb5_data *) malloc(sizeof(*princ_ret[i])))) {
	free_out:
	    for (i--; i >= 0; i--) {
		xfree(princ_ret[i]->data);
		xfree(princ_ret[i]);
	    }
	    xfree(princ_ret);
	    return (ENOMEM);
	}
	princ_ret[i]->length = strlen(next);
	princ_ret[i]->data = strdup(next);
	if (!princ_ret[i]->data) {
	    xfree(princ_ret[i]);
	    goto free_out;
	}
    }
    princ_ret[i] = 0;			/* put a null as the last entry */
    *princ = princ_ret;
    return 0;
}

krb5_error_code
#if __STDC__ || defined(STDARG_PROTOTYPES)
krb5_build_principal(krb5_principal *princ, int rlen, const char *realm, ...)
#else
krb5_build_principal(princ, rlen, realm, va_alist)
krb5_principal *princ;
int rlen;
const char *realm;
va_dcl
#endif
{
    va_list ap;
    krb5_error_code retval;

#if __STDC__ || defined(STDARG_PROTOTYPES)
    va_start(ap, realm);
#else
    va_start(ap);
#endif
    retval = krb5_build_principal_va(princ, rlen, realm, ap);
    va_end(ap);
    return retval;
}
