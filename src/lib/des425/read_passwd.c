/*
 * lib/des425/read_passwd.c
 *
 * Copyright 1985,1986,1987,1988,1991 by the Massachusetts Institute
 * of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This routine prints the supplied string to standard
 * output as a prompt, and reads a password string without
 * echoing.
 */

#include "des.h"

static krb5_context krb4_global_context = 0;

/*** Routines ****************************************************** */
int INTERFACE
des_read_password/*_v4_compat_crock*/(k,prompt,verify)
    mit_des_cblock *k;
    char *prompt;
    int	verify;
{
    krb5_error_code ok;
    krb5_error_code retval;
    char key_string[BUFSIZ];
    char prompt2[BUFSIZ];
    int string_size = sizeof(key_string);

    if (!krb4_global_context) {
	    retval = krb5_init_context(&krb4_global_context);
	    if (retval)
		    return retval;
    }

    if (verify) {
	strcpy(prompt2, "Verifying, please re-enter ");
	strncat(prompt2, prompt, sizeof(prompt2)-(strlen(prompt2)+1));
    }
    ok = krb5_read_password(krb4_global_context, prompt, verify ? prompt2 : 0,
			    key_string, &string_size);
    
    if (ok == 0)
	des_string_to_key(key_string, k);

    memset(key_string, 0, sizeof (key_string));
    return ok;
}
