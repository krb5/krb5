#include "k5-int.h"
#include "com_err.h"

static krb5_error_code
krb5_get_as_key_password(context, client, etype, prompter, prompter_data,
			 salt, as_key, gak_data)
     krb5_context context;
     krb5_principal client;
     krb5_enctype etype;
     krb5_prompter_fct prompter;
     void *prompter_data;
     krb5_data *salt;
     krb5_keyblock *as_key;
     void *gak_data;
{
    krb5_data *password;
    krb5_error_code ret;
    krb5_data defsalt;
    krb5_encrypt_block eblock;
    char *clientstr;
    char promptstr[1024];
    krb5_prompt prompt;

    password = (krb5_data *) gak_data;

    /* if there's already a key of the correct etype, we're done.
       if the etype is wrong, free the existing key, and make
       a new one. */

    if (as_key->length) {
	if (as_key->enctype == etype)
	    return(0);

	krb5_free_keyblock_contents(context, as_key);
	as_key->length = 0;
    }

    if (!valid_enctype(etype))
	return(KRB5_PROG_ETYPE_NOSUPP);

    krb5_use_enctype(context, &eblock, etype);

    if (password->data[0] == '\0') {
	if (prompter == NULL)
	    return(EIO);

	if (ret = krb5_unparse_name(context, client, &clientstr))
	    return(ret);

	strcpy(promptstr, "Password for ");
	strncat(promptstr, clientstr, sizeof(promptstr)-strlen(promptstr)-1);
	promptstr[sizeof(promptstr)-1] = '\0';

	free(clientstr);

	prompt.prompt = promptstr;
	prompt.hidden = 1;
	prompt.reply = password;

	if (ret = ((*prompter)(context, prompter_data, NULL, 1, &prompt)))
	    return(ret);
    }

    if ((salt->length == -1) && (salt->data == NULL)) {
	if (ret = krb5_principal2salt(context, client, &defsalt))
	    return(ret);

	salt = &defsalt;
    } else {
	defsalt.length = 0;
    }

    ret = krb5_string_to_key(context, &eblock, as_key, password, salt);

    if (defsalt.length)
	krb5_xfree(defsalt.data);

    return(ret);
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_password(context, creds, client, password, prompter, data,
			     start_time, in_tkt_service, options)
     krb5_context context;
     krb5_creds *creds;
     krb5_principal client;
     char *password;
     krb5_prompter_fct prompter;
     void *data;
     krb5_deltat start_time;
     char *in_tkt_service;
     krb5_get_init_creds_opt *options;
{
   krb5_error_code ret, ret2;
   int master;
   krb5_kdc_rep *as_reply;
   int tries;
   krb5_creds chpw_creds;
   krb5_get_init_creds_opt chpw_opts;
   krb5_data pw0, pw1;
   char banner[1024], pw0array[1024], pw1array[1024];
   krb5_prompt prompt[2];

   master = 0;
   as_reply = NULL;
   memset(&chpw_creds, 0, sizeof(chpw_creds));

   pw0.data = pw0array;

   if (password) {
      if ((pw0.length = strlen(password)) > sizeof(pw0array)) {
	 ret = EINVAL;
	 goto cleanup;
      }
      strcpy(pw0.data, password);
   } else {
      pw0.data[0] = '\0';
      pw0.length = sizeof(pw0array);
   }

   pw1.data = pw1array;
   pw1.data[0] = '\0';
   pw1.length = sizeof(pw1array);

   /* first try: get the requested tkt from any kdc */

   ret = krb5_get_init_creds(context, creds, client, prompter, data,
			     start_time, in_tkt_service, options,
			     krb5_get_as_key_password, (void *) &pw0,
			     &master, &as_reply);

   /* check for success */

   if (ret == 0)
      goto cleanup;

   /* If all the kdc's are unavailable, or if the error was due to a
      user interrupt, fail */

   if ((ret == KRB5_KDC_UNREACH) ||
       (ret == KRB5_LIBOS_PWDINTR))
      goto cleanup;

   /* if the reply did not come from the master kdc, try again with
      the master kdc */

   if (!master) {
      master = 1;

      ret2 = krb5_get_init_creds(context, creds, client, prompter, data,
				 start_time, in_tkt_service, options,
				 krb5_get_as_key_password, (void *) &pw0,
				 &master, &as_reply);
      
      if (ret2 == 0) {
	 ret = 0;
	 goto cleanup;
      }

      /* if the master is unreachable, return the error from the
	 slave we were able to contact */

      if (ret2 == KRB5_KDC_UNREACH)
	 goto cleanup;

      ret = ret2;
   }

   /* at this point, we have an error from the master.  if the error
      is not password expired, or if it is but there's no prompter,
      return this error */

   if ((ret != KRB5KDC_ERR_KEY_EXP) ||
       (prompter == NULL))
      goto cleanup;

   /* ok, we have an expired password.  Give the user a few chances
      to change it */

   /* use a minimal set of options */

   krb5_get_init_creds_opt_init(&chpw_opts);
   krb5_get_init_creds_opt_set_tkt_life(&chpw_opts, 5*60);
   krb5_get_init_creds_opt_set_renew_life(&chpw_opts, 0);
   krb5_get_init_creds_opt_set_forwardable(&chpw_opts, 0);
   krb5_get_init_creds_opt_set_proxiable(&chpw_opts, 0);

   if (ret = krb5_get_init_creds(context, &chpw_creds, client,
				 prompter, data,
				 start_time, "kadmin/changepw", &chpw_opts,
				 krb5_get_as_key_password, (void *) &pw0,
				 &master, NULL))
      goto cleanup;

   prompt[0].prompt = "Enter new password";
   prompt[0].hidden = 1;
   prompt[0].reply = &pw0;

   prompt[1].prompt = "Enter it again";
   prompt[1].hidden = 1;
   prompt[1].reply = &pw1;

   strcpy(banner, "Password expired.  You must change it now.");

   for (tries = 3; tries; tries--) {
      pw0.length = sizeof(pw0array);
      pw1.length = sizeof(pw1array);

      if (ret = ((*prompter)(context, data, banner,
			     sizeof(prompt)/sizeof(prompt[0]), prompt)))
	 goto cleanup;

      if (strcmp(pw0.data, pw1.data) != 0) {
	 ret = KRB5_LIBOS_BADPWDMATCH;
	 sprintf(banner, "%s.  Please try again.", error_message(ret));
      } else if (pw0.length == 0) {
	 ret = KRB5_CHPW_PWDNULL;
	 sprintf(banner, "%s.  Please try again.", error_message(ret));
      } else {
	 int result_code;
	 krb5_data code_string;
	 krb5_data result_string;

	 if (ret = krb5_change_password(context, &chpw_creds, pw0array,
					&result_code, &code_string,
					&result_string))
	    goto cleanup;

	 /* the change succeeded.  go on */

	 if (result_code == 0) {
	    krb5_xfree(result_string.data);
	    break;
	 }

	 /* set this in case the retry loop falls through */

	 ret = KRB5_CHPW_FAIL;

	 if (result_code != KRB5_KPASSWD_SOFTERROR) {
	    krb5_xfree(result_string.data);
	    goto cleanup;
	 }

	 /* the error was soft, so try again */

	 /* 100 is I happen to know that no code_string will be longer
	    than 100 chars */

	 if (result_string.length > (sizeof(banner)-100))
	    result_string.length = sizeof(banner)-100;

	 sprintf(banner, "%.*s%s%.*s.  Please try again.\n",
		 code_string.length, code_string.data,
		 result_string.length?": ":"",
		 result_string.length, result_string.data);

	 krb5_xfree(code_string.data);
	 krb5_xfree(result_string.data);
      }
   }

   if (ret)
      goto cleanup;

   /* the password change was successful.  Get an initial ticket
      from the master.  this is the last try.  the return from this
      is final.  */

   ret = krb5_get_init_creds(context, creds, client, prompter, data,
			     start_time, in_tkt_service, options,
			     krb5_get_as_key_password, (void *) &pw0,
			     &master, &as_reply);

cleanup:
   /* if getting the password was successful, then check to see if the
      password is about to expire, and warn if so */

   if (ret == 0) {
      krb5_timestamp now;
      int hours;

      /* XXX 7 days should be configurable.  This is all pretty ad hoc,
	 and could probably be improved if I was willing to screw around
	 with timezones, etc. */

      if (prompter &&
	  (in_tkt_service &&
	   (strcmp(in_tkt_service, "kadmin/changepw") != 0)) &&
	  ((ret = krb5_timeofday(context, &now)) == 0) &&
	  as_reply->enc_part2->key_exp &&
	  ((hours = ((as_reply->enc_part2->key_exp-now)/(60*60))) <= 7*24) &&
	  (hours >= 0)) {
	 if (hours < 1)
	    sprintf(banner,
		    "Warning: Your password will expire in less than one hour.");
	 else if (hours <= 48)
	    sprintf(banner, "Warning: Your password will expire in %d hour%s.",
		    hours, (hours == 1)?"":"s");
	 else
	    sprintf(banner, "Warning: Your password will expire in %d days.",
		    hours/24);

	 /* ignore an error here */
	 (*prompter)(context, data, banner, 0, 0);
      }
   }

   memset(pw0array, 0, sizeof(pw0array));
   memset(pw1array, 0, sizeof(pw1array));
   krb5_free_cred_contents(context, &chpw_creds);
   if (as_reply)
      krb5_free_kdc_rep(context, as_reply);

   return(ret);
}
