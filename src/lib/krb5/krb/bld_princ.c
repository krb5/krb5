/*
 * lib/krb5/krb/bld_princ.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Build a principal from a list of strings
 */

#include <stdarg.h>
#include "k5-int.h"

/* Takes first component as argument for KIM API, 
 * which does not allow realms with zero components */
static krb5_error_code
krb5int_build_principal_va(krb5_context context, 
                           krb5_principal princ, 
                           unsigned int rlen, 
                           const char *realm, 
                           const char *first,
                           va_list ap)
{
    krb5_error_code retval = 0;
    char *r = NULL;
    krb5_data *data = NULL;
    krb5_int32 count = 0;
    krb5_int32 size = 2;  /* initial guess at needed space */
    char *component = NULL;
    
    data = malloc(size * sizeof(krb5_data));
    if (!data) { retval = ENOMEM; }
    
    if (!retval) {
        r = strdup(realm);
        if (!r) { retval = ENOMEM; }
    }
    
    if (!retval && first) {
        data[0].length = strlen(first);
        data[0].data = strdup(first);
        if (!data[0].data) { retval = ENOMEM; }
        count++;
        
        /* ap is only valid if first is non-NULL */
        while (!retval && (component = va_arg(ap, char *))) {
            if (count == size) {
                krb5_data *new_data = NULL;
                
                size *= 2;
                new_data = realloc ((char *) data, sizeof(krb5_data) * size);
                if (new_data) {
                    data = new_data;
                } else {
                    retval = ENOMEM;
                }
            }
            
            if (!retval) {
                data[count].length = strlen(component);
                data[count].data = strdup(component);  
                if (!data[count].data) { retval = ENOMEM; }
                count++;
            }
        }
    }
    
    if (!retval) {
        princ->type = KRB5_NT_UNKNOWN;
        princ->magic = KV5M_PRINCIPAL;
        krb5_princ_set_realm_data(context, princ, r);
        krb5_princ_set_realm_length(context, princ, strlen(r));
        princ->data = data;
        princ->length = count;
        r = NULL;    /* take ownership */
        data = NULL; /* take ownership */
    }
    
    if (data) {
        while (--count >= 0) {
            krb5_xfree(data[count].data);
        }
        krb5_xfree(data);
    }
    krb5_xfree(r);
    
    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_build_principal_va(krb5_context context, 
                        krb5_principal princ, 
                        unsigned int rlen, 
                        const char *realm, 
                        va_list ap)
{
    char *first = va_arg(ap, char *);
    
    return krb5int_build_principal_va(context, princ, rlen, realm, first, ap);
}

/* Takes first component as argument for KIM API, 
 * which does not allow realms with zero components */
krb5_error_code KRB5_CALLCONV
krb5int_build_principal_alloc_va(krb5_context context, 
                                 krb5_principal *princ, 
                                 unsigned int rlen, 
                                 const char *realm, 
                                 const char *first,
                                 va_list ap)
{
    krb5_error_code retval = 0;
    
    krb5_principal p = malloc(sizeof(krb5_principal_data));
    if (!p) { retval = ENOMEM; }
    
    if (!retval) {
        retval = krb5int_build_principal_va(context, p, rlen, realm, first, ap);
    }
    
    if (!retval) {
	*princ = p;
    } else {
        krb5_xfree(p);
    }
    
    return retval;    
}

krb5_error_code KRB5_CALLCONV
krb5_build_principal_alloc_va(krb5_context context, 
                              krb5_principal *princ, 
                              unsigned int rlen, 
                              const char *realm, 
                              va_list ap)
{
    krb5_error_code retval = 0;
    
    krb5_principal p = malloc(sizeof(krb5_principal_data));
    if (!p) { retval = ENOMEM; }
   
    if (!retval) {
        retval = krb5_build_principal_va(context, p, rlen, realm, ap);
    }
    
    if (!retval) {
	*princ = p;
    } else {
        krb5_xfree(p);
    }

    return retval;
}

krb5_error_code KRB5_CALLCONV_C
krb5_build_principal(krb5_context context, 
                     krb5_principal * princ, 
		     unsigned int rlen,
		     const char * realm, ...)
{
    krb5_error_code retval = 0;
    va_list ap;
    
    va_start(ap, realm);
    retval = krb5_build_principal_alloc_va(context, princ, rlen, realm, ap);
    va_end(ap);
    
    return retval;
}
