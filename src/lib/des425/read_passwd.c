/*
 * $Source$
 * $Author$
 *
 * Copyright 1985,1986,1987,1988,1991 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This routine prints the supplied string to standard
 * output as a prompt, and reads a password string without
 * echoing.
 */

#ifndef	lint
static char rcsid_read_password_c[] =
"$Id$";
#endif	/* lint */

#include <krb5/krb5.h>
#include <krb5/los-proto.h>

#include "des.h"

/*** Routines ****************************************************** */
int
des_read_password/*_v4_compat_crock*/(k,prompt,verify)
    mit_des_cblock *k;
    char *prompt;
    int	verify;
{
    int ok;
    char key_string[BUFSIZ];
    char prompt2[BUFSIZ];
    int string_size = sizeof(key_string);
    krb5_error_code retval;

    if (verify) {
	strcpy(prompt2, "Verifying, please re-enter ");
	strncat(prompt2, prompt, sizeof(prompt2)-(strlen(prompt2)+1));
    }
    ok = krb5_read_password(prompt, verify ? prompt2 : 0,
			    key_string, &string_size);
    
    if (ok == 0)
	des_string_to_key(key_string, k);

    bzero(key_string, sizeof (key_string));
    return ok;
}
