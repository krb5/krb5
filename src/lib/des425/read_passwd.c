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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This routine prints the supplied string to standard
 * output as a prompt, and reads a password string without
 * echoing.
 */

#if !defined(_WIN32)

#include "des_int.h"
#include "des.h"
#include <stdio.h>
#include <errno.h>
#include <krb5.h>
/* This is re-declared here because des.h might not declare it. */
int KRB5_CALLCONV des_read_pw_string(char *, int, char *, int);
static int des_rd_pwstr_2prompt(char *, int, char *, char *);


/*** Routines ****************************************************** */
static int
des_rd_pwstr_2prompt(return_pwd, bufsize_in, prompt, prompt2)
    char *return_pwd;
    int bufsize_in;
    char *prompt;
    char *prompt2;
{
    krb5_data reply_data;      
    krb5_prompt k5prompt;
    krb5_error_code retval;
    reply_data.length = bufsize_in;
    reply_data.data = return_pwd;
    k5prompt.prompt = prompt;
    k5prompt.hidden = 1;
    k5prompt.reply = &reply_data;
    retval =  krb5_prompter_posix(NULL,
				  NULL, NULL, NULL, 1, &k5prompt);

    if ((retval==0) && prompt2) {
	krb5_data verify_data;
	verify_data.data = malloc(bufsize_in);
	verify_data.length = bufsize_in;
	k5prompt.prompt = prompt2;
	k5prompt.reply = &verify_data;
	if (!verify_data.data)
	    return ENOMEM;
	retval = krb5_prompter_posix(NULL,
				     NULL,NULL, NULL, 1, &k5prompt);
	if (retval) {
	    free(verify_data.data);
	} else {
	    /* compare */
	    if (strncmp(return_pwd, (char *)verify_data.data, bufsize_in)) {
		retval = KRB5_LIBOS_BADPWDMATCH;
		free(verify_data.data);
	    }
	}
    }
    return retval;
}


int KRB5_CALLCONV
des_read_password(k,prompt,verify)
    mit_des_cblock *k;
    char *prompt;
    int	verify;
{
    int ok;
    char key_string[BUFSIZ];

    ok = des_read_pw_string(key_string, sizeof(key_string), prompt, verify);
    if (ok == 0)
	des_string_to_key(key_string, *k);

    memset(key_string, 0, sizeof (key_string));
    return ok;
}

/* Note: this function is exported on KfM.  Do not change its ABI. */
int KRB5_CALLCONV
des_read_pw_string(s, max, prompt, verify)
    char *s;
    int max;
    char *prompt;
    int	verify;
{
    int ok;
    char prompt2[BUFSIZ];

    if (verify) {
	snprintf(prompt2, sizeof(prompt2), "Verifying, please re-enter %s",
		 prompt);
    }
    ok = des_rd_pwstr_2prompt(s, max, prompt, verify ? prompt2 : 0);
    return ok;
}

#else /* !unix */
/*
 * These are all just dummy functions to make the rest of the library happy...
 */
#endif /* _WINDOWS */
