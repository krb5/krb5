/*
 * Copyright 1993-1994 OpenVision Technologies, Inc., All Rights Reserved.
 * 
 * $Header$
 *
 *
 */

static char rcsid[] = "$Id$";

#include <kadm5/admin.h>
#include <krb5.h>

#include "kpasswd_strings.h"
#define string_text error_message
#define initialize_kpasswd_strings initialize_kpws_error_table

#include <stdio.h>
#include <pwd.h>
#include <string.h>

char *whoami;

void display_intro_message(fmt_string, arg_string)
     char *fmt_string;
     char *arg_string;
{
  com_err(whoami, 0, fmt_string, arg_string);
}

long read_old_password(context, password, pwsize)
     krb5_context context;
     char *password;
     int *pwsize;
{
  long code = krb5_read_password(context,
			 (char *)string_text(KPW_STR_OLD_PASSWORD_PROMPT),  
			 0, password, pwsize);
  return code;
}

long read_new_password(server_handle, password, pwsize, msg_ret, princ)
     void *server_handle;
     char *password;
     int *pwsize;
     char *msg_ret;
     krb5_principal princ;
{
  return (ovsec_kadm_chpass_principal_util(server_handle, princ, NULL, 
					   NULL /* don't need new pw back */,
					   msg_ret));
}


/*
 * main() for tty version of kpasswd.c
 */
int
main(argc, argv)
     int argc;
     char *argv[];
{
  krb5_context context;
  int retval;

  initialize_kpasswd_strings();

  whoami = (whoami = strrchr(argv[0], '/')) ? whoami + 1 : argv[0];

  if (retval = krb5_init_context(&context)) {
       com_err(whoami, retval, "initializing krb5 context");
       exit(retval);
  }
  retval = kpasswd(context, argc, argv);

  if (!retval)
    printf(string_text(KPW_STR_PASSWORD_CHANGED));

  exit(retval);
}
