/*
 * kadmin/kpasswd/kpasswd.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 */

/*
 * kpasswd
 * change your password with Version 5 Kerberos using the new password
 * changing protocol.
 */

/*
 * Include files.
 */
#include "k5-int.h"
#include "adm_defs.h"
#include "adm.h"
#include "krb5/adm_proto.h"

#ifdef	HAVE_STRING_H
#include <string.h>
#else	/* HAVE_STRING_H */
#include <strings.h>
#endif	/* HAVE_STRING_H */


/*
 * Local definitions.
 */
#define	KPWD_MAX_TRIES		4

/*
 * Local data.
 */
#define kpwd_serror_head		"server"
#define kpwd_change_prompt_1		"   Enter new password"
#define kpwd_change_prompt_2		"Re-enter new password"
#define kpwd_old_password_prompt	"   Enter old password"
#define kpwd_old_pwd_name_fmt		"Enter old password for %s"

#ifdef	LANGUAGES_SUPPORTED
#define kpwd_usage_error_fmt		"%s: usage is %s [-u user] [-l language]\n"
#define kpwd_getoptstring		"l:u:"
#else	/* LANGUAGES_SUPPORTED */
#define kpwd_usage_error_fmt		"%s: usage is %s [-u user]\n"
#define kpwd_getoptstring		"u:"
#endif	/* LANGUAGES_SUPPORTED */
#define kpwd_extra_args			"extra arguments"
#if 0
#define kpwd_bad_option_fmt		"%s: unrecognized option -%c.\n"
#endif
#define kpwd_no_memory_fmt		"%s: not enough resources to allocate %d bytes for %s.\n"
#define kpwd_bad_client_fmt		"%s: %s%s%s %s not recognized by the server.\n"
#define kpwd_no_server_fmt		"%s: cannot find server for %s.\n"
#define kpwd_incorrect_fmt		"%s: incorrect password\n"
#define kpwd_cant_connect_fmt		"%s: cannot contact server (%s).\n"
#define kpwd_proto_error_fmt		"%s: protocol error during %s request (%s).\n"
#define kpwd_pwproto_unsupp_fmt		"%s: %s request not supported by server.\n"
#define kpwd_pwproto_error		"%s: server error (%s) during %s request.\n"
#define kpwd_pwd_unacceptable		"%s: your new password is unacceptable to the server, %s.\n"
#define kpwd_read_pass_error		"%s: error (%s) reading passwords.\n"

static const char *kpwd_password_text = "passwords";
#if 0
static const char *kpwd_realm_text = "realm name";
#endif
static const char *kpwd_args_text = "arguments";

static const char *kpwd_try_again_text = "try again";
static const char *kpwd_seeyalater_text = "password not changed";

#if 0
static const char *kpwd_mime_text = "MIME-enable";
static const char *kpwd_language_text = "set language";
#endif
static const char *kpwd_check_pwd_text = "check password";
static const char *kpwd_change_pwd_text = "change password";
static const char *kpwd_quit_text = "quit";

static const char *kpwd_you = "you";
static const char *kpwd_is_second = "are";
static const char *kpwd_is_third = "is";
static const char *kpwd_quote = "'";
static const char *kpwd_null = "";

static const char *kpwd_this_realm = "this realm";

static const char *kpwd_replies[] = {
    "Operation successful",		/* KRB5_ADM_SUCCESS */
    "Command not recognized",		/* KRB5_ADM_CMD_UNKNOWN */
    "Password unacceptable to server",	/* KRB5_ADM_PW_UNACCEPT */
    "Old password incorrect",		/* KRB5_ADM_BAD_PW */
    "Invalid ticket (TKT_FLAG_INITIAL not set)",/* KRB5_ADM_NOT_IN_TKT */
    "Server refused password change",	/* KRB5_ADM_CANT_CHANGE */
    "Language not supported",		/* KRB5_ADM_LANG_NOT_SUPPORTED */
};
static const char *kpwd_replies_unknown = "UNKNOWN ERROR";

static void
usage(invocation, more_info)
    char *invocation;
    char *more_info;
{
    if (more_info)
	fprintf(stderr, "%s: %s\n", invocation, more_info);
    fprintf(stderr, kpwd_usage_error_fmt, invocation, invocation);
}

static const char *
kpwd_reply_to_string(status)
    krb5_int32	status;
{
    int	idx;
    const char *rval;

    switch (status) {
    case KRB5_ADM_SUCCESS:
    case KRB5_ADM_CMD_UNKNOWN:
    case KRB5_ADM_PW_UNACCEPT:
    case KRB5_ADM_BAD_PW:
    case KRB5_ADM_NOT_IN_TKT:
    case KRB5_ADM_CANT_CHANGE:
    case KRB5_ADM_LANG_NOT_SUPPORTED:
	idx = (int) status;
	rval = kpwd_replies[idx];
	break;
    default:
	rval = kpwd_replies_unknown;
	break;
    }
    return(rval);
}

static void
kpwd_print_sreply(progname, ncomps, complist)
    char	*progname;
    krb5_int32	ncomps;
    krb5_data	*complist;
{
    krb5_int32	i;
    /*
     * If language/mime suporrt enabled, need to have mime-decoder here.
     */
    if (ncomps > 0) {
	fprintf(stderr, "%s - %s: %s\n", progname, kpwd_serror_head,
		complist[0].data);
	for (i=1; i<ncomps; i++)
	    fprintf(stderr, "\t%s\n", complist[i].data);
    }
}

int
main(argc, argv)
    int argc;
    char *argv[];
{
    int			option;
    extern int		optind;
    extern char		*optarg;
    int			error;

    char		*name;
#ifdef	LANGUAGES_SUPPORTED
    int			mflag;
    int			lflag;
#endif
    char 		*language;

    krb5_error_code	kret;
    krb5_context	kcontext;
    krb5_auth_context	auth_context;
    krb5_ccache		ccache;
    char		*opassword;
    char		*npassword;
    char		*opwd_prompt;

    int			conn_socket = -1;

    int			npass_tries;
    int			send_quit;

    /*
     * Initialize.
     */
    language = name = opwd_prompt = (char *) NULL;
    error = 0;
#ifdef	LANGUAGES_SUPPORTED
    mflag = lflag = 0;
#endif
    send_quit = 0;
    ccache = (krb5_ccache) NULL;

    /*
     * Usage is:
     *	kpasswd [-u user] [-l language]
     */
    while ((option = getopt(argc, argv, kpwd_getoptstring)) != -1) {
	switch (option) {
	case 'u':
	    if ((name = (char *) malloc(strlen(optarg)+1)) == NULL) {
		fprintf(stderr, kpwd_no_memory_fmt, argv[0], 
			strlen(optarg)+1, kpwd_args_text);
		error = ENOMEM;
		break;
	    }
	    strcpy(name, optarg);
	    break;
#ifdef	LANGUAGES_SUPPORTED
	case 'l':
	    lflag++;
	    mflag++;
	    if ((language = (char *) malloc(strlen(optarg)+1)) == NULL) {
		fprintf(stderr, kpwd_no_memory_fmt, argv[0], 
			strlen(optarg)+1, kpwd_args_text);
		error = ENOMEM;
		break;
	    }
	    strcpy(language, optarg);
	    break;
#endif	/* LANGUAGES_SUPPORTED */
	default:
	    error++;
	    break;
	}
	if (error)
	    break;
    }
    if (error || ((argc - optind) > 0)) {
	usage(argv[0], (error) ? (char *) NULL: kpwd_extra_args);
	error++;
	if (name)
	    free(name);
	if (language)
	    free(language);
	return(error);
    }

    /*
     * Initialize Kerberos
     */
    kret = krb5_init_context(&kcontext);
    if (kret) {
	com_err(argv[0], kret, "while initializing krb5");
	exit(1);
    }

    /* Get space for passwords */
    if (
	((npassword = (char *) malloc(KRB5_ADM_MAX_PASSWORD_LEN)) 
	== (char *) NULL) ||
	((opassword = (char *) malloc(KRB5_ADM_MAX_PASSWORD_LEN)) 
	== (char *) NULL))
    {
	fprintf(stderr, kpwd_no_memory_fmt, argv[0], KRB5_ADM_MAX_PASSWORD_LEN,
		kpwd_password_text);
	if (npassword)
	    free(npassword);
	krb5_free_context(kcontext);
	return(ENOMEM);
    }

    /* From now on, all error legs via 'goto cleanup' */

    if (name) {
	size_t prompt_len;

	prompt_len = strlen(kpwd_old_pwd_name_fmt) - 2 + strlen(name) + 1;
	opwd_prompt = (char *) malloc(prompt_len);
	if (opwd_prompt)
	    sprintf(opwd_prompt, kpwd_old_pwd_name_fmt, name);
    }
    /*
     * Establish the connection.
     */
    kret = krb5_adm_connect(kcontext, name, 
			    (opwd_prompt) ? 
			    opwd_prompt : kpwd_old_password_prompt,
			    opassword, &conn_socket, &auth_context,
				&ccache, (char *) NULL, 0);
    if (kret) {
	switch (kret) {
	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
	    fprintf(stderr, kpwd_bad_client_fmt, argv[0],
		    (name) ? kpwd_quote : kpwd_null,
		    (name) ? name : kpwd_you,
		    (name) ? kpwd_quote : kpwd_null,
		    (name) ? kpwd_is_third : kpwd_is_second);
	    break;
	case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
	    fprintf(stderr, kpwd_no_server_fmt, argv[0],
		    (name) ? name : kpwd_this_realm);
	    break;
	case KRB5KRB_AP_ERR_BAD_INTEGRITY:
	    fprintf(stderr, kpwd_incorrect_fmt, argv[0]);
	    break;
	default:
	    fprintf(stderr, kpwd_cant_connect_fmt, argv[0],
		    error_message(kret));
	    break;
	}
	goto cleanup;
    }

    if (opwd_prompt)
	free(opwd_prompt);
    send_quit = 1;

#ifdef	LANGUAGES_SUPPORTED
    /*
     * We have the connection - see if we have to send some precursory data.
     */
    if (mflag) {
	/*
	 * Need to engage in protocol for MIME setting
	 */
	krb5_data	mime_data;
	krb5_int32	mime_status;
	krb5_int32	mime_ncomps;
	krb5_data	*mime_reply;

	mime_data.data = KRB5_ADM_MIME_CMD;
	mime_data.length = strlen(mime_data.data);
	if ((kret = krb5_send_adm_cmd(kcontext,
				      &conn_socket,
				      auth_context,
				      1,
				      &mime_data)) ||
	    (kret = krb5_read_adm_reply(kcontext,
					&conn_socket,
					auth_context,
					&mime_status,
					&mime_ncomps,
					&mime_reply))) {
	    fprintf(stderr, kpwd_proto_error_fmt, argv[0], kpwd_mime_text,
		    error_message(kret));
	    send_quit = 0;
	    goto cleanup;
	}
	switch (mime_status) {
	case KRB5_ADM_SUCCESS:
	    break;
	case KRB5_ADM_CMD_UNKNOWN:
	    fprintf(stderr, kpwd_pwproto_unsupp_fmt, argv[0], kpwd_mime_text);
	    if (mime_ncomps > 0)
		kpwd_print_sreply(argv[0], mime_ncomps, mime_reply);
	    break;
	default:
	    fprintf(stderr, kpwd_pwproto_error, argv[0],
		    kpwd_reply_to_string(mime_status), kpwd_mime_text);
	    if (mime_ncomps > 0)
		kpwd_print_sreply(argv[0], mime_ncomps, mime_reply);
	    goto cleanup;
	}
	krb5_free_adm_data(kcontext, mime_ncomps, mime_reply);
    }
    if (lflag && language) {
	/*
	 * Need to engage in protocol for language setting
	 */
	krb5_data	lang_data[2];
	krb5_int32	lang_status;
	krb5_int32	lang_ncomps;
	krb5_data	*lang_reply;

	lang_data[0].data = KRB5_ADM_LANGUAGE_CMD;
	lang_data[0].length = strlen(lang_data[0].data);
	lang_data[1].data = language;
	lang_data[1].length = strlen(language);
	if ((kret = krb5_send_adm_cmd(kcontext,
				      &conn_socket,
				      auth_context,
				      2,
				      lang_data)) ||
	    (kret = krb5_read_adm_reply(kcontext,
					&conn_socket,
					auth_context,
					&lang_status,
					&lang_ncomps,
					&lang_reply))) {
	    fprintf(stderr, kpwd_proto_error_fmt, argv[0], kpwd_language_text,
		    error_message(kret));
	    send_quit = 0;
	    goto cleanup;
	}
	switch (lang_status) {
	case KRB5_ADM_SUCCESS:
	    break;
	case KRB5_ADM_CMD_UNKNOWN:
	    fprintf(stderr, kpwd_pwproto_unsupp_fmt, argv[0],
		    kpwd_language_text);
	    if (lang_ncomps > 0)
		kpwd_print_sreply(argv[0], lang_ncomps, lang_reply);
	    break;
	default:
	    fprintf(stderr, kpwd_pwproto_error, argv[0],
		    kpwd_reply_to_string(lang_status), kpwd_language_text);
	    if (lang_ncomps > 0)
		kpwd_print_sreply(argv[0], lang_ncomps, lang_reply);
	    goto cleanup;
	}
	krb5_free_adm_data(kcontext, lang_ncomps, lang_reply);
    }
#endif	/* LANGUAGES_SUPPORTED */

    /* Now - Actually change the password. */
    for (npass_tries = 1; npass_tries <= KPWD_MAX_TRIES; npass_tries++) {
	unsigned int npass_len;

	npass_len = KRB5_ADM_MAX_PASSWORD_LEN;
	if (!(kret = krb5_read_password(kcontext,
					kpwd_change_prompt_1,
					kpwd_change_prompt_2,
					npassword,
					&npass_len))) {
	    krb5_data		check_data[2];
	    krb5_int32		check_status;
	    krb5_int32		check_ncomps;
	    krb5_data		*check_reply;
	    krb5_data		set_data[3];
	    krb5_int32		set_status;
	    krb5_int32		set_ncomps;
	    krb5_data		*set_reply;

	    check_data[0].data = KRB5_ADM_CHECKPW_CMD;
	    check_data[0].length = strlen(check_data[0].data);
	    check_data[1].data = npassword;
	    check_data[1].length = npass_len;
	    if ((kret = krb5_send_adm_cmd(kcontext,
					  &conn_socket,
					  auth_context,
					  2,
					  check_data)) ||
		(kret = krb5_read_adm_reply(kcontext,
					    &conn_socket,
					    auth_context,
					    &check_status,
					    &check_ncomps,
					    &check_reply))) {
		fprintf(stderr, kpwd_proto_error_fmt, argv[0], 
			kpwd_check_pwd_text, error_message(kret));
		send_quit = 0;
		error++;
		break;
	    }
	    if ((check_status != KRB5_ADM_SUCCESS) &&
		(check_status != KRB5_ADM_PW_UNACCEPT)) {
		error++;
		fprintf(stderr, kpwd_pwproto_error, argv[0],
			kpwd_reply_to_string(check_status),
			kpwd_check_pwd_text);
		if (check_ncomps > 0)
		    kpwd_print_sreply(argv[0], check_ncomps, check_reply);
	    }

	    if (check_status == KRB5_ADM_PW_UNACCEPT) {
		fprintf(stderr, kpwd_pwd_unacceptable, argv[0],
			(npass_tries < KPWD_MAX_TRIES) ? 
			kpwd_try_again_text : kpwd_seeyalater_text);
		if (check_ncomps > 0)
		    kpwd_print_sreply(argv[0], check_ncomps, check_reply);
		if (npass_tries == KPWD_MAX_TRIES)
		    kret = check_status;
		continue;
	    }
	    krb5_free_adm_data(kcontext, check_ncomps, check_reply);
	    if (error)
		break;

	    /* Now actually change the password */
	    set_data[0].data = KRB5_ADM_CHANGEPW_CMD;
	    set_data[0].length = strlen(set_data[0].data);
	    set_data[1].data = opassword;
	    set_data[1].length = strlen(opassword);
	    set_data[2].data = npassword;
	    set_data[2].length = npass_len;
	    if ((kret = krb5_send_adm_cmd(kcontext,
					  &conn_socket,
					  auth_context,
					  3,
					  set_data)) ||
		(kret = krb5_read_adm_reply(kcontext,
					    &conn_socket,
					    auth_context,
					    &set_status,
					    &set_ncomps,
					    &set_reply))) {
		fprintf(stderr, kpwd_proto_error_fmt, argv[0], 
			kpwd_change_pwd_text, error_message(kret));
		send_quit = 0;
		error++;
		break;
	    }
	    if (set_status != KRB5_ADM_SUCCESS) {
		fprintf(stderr, kpwd_pwproto_error, argv[0],
			kpwd_reply_to_string(set_status),
			kpwd_change_pwd_text);
		if (set_ncomps > 0)
		    kpwd_print_sreply(argv[0], set_ncomps, set_reply);
		error++;
	    }
	    krb5_free_adm_data(kcontext, set_ncomps, set_reply);
	    break;
	}
	else {
	    fprintf(stderr, kpwd_read_pass_error, argv[0],
		    error_message(kret));
	    error++;
	    break;
	}
    }

 cleanup:
    if (kret)
	error = kret;
    if (language)
	free(language);
    if (name)
	free(name);

    /* Clear and free password storage */
    if (opassword) {
	memset(opassword, 0, KRB5_ADM_MAX_PASSWORD_LEN);
	free(opassword);
    }
    if (npassword) {
	memset(npassword, 0, KRB5_ADM_MAX_PASSWORD_LEN);
	free(npassword);
    }

    if (send_quit) {
	/*
	 * Need to send quit command.
	 */
	krb5_data	quit_data;
	krb5_int32	quit_status;
	krb5_int32	quit_ncomps;
	krb5_data	*quit_reply;
	
	quit_data.data = KRB5_ADM_QUIT_CMD;
	quit_data.length = strlen(quit_data.data);
	if ((kret = krb5_send_adm_cmd(kcontext,
				      &conn_socket,
				      auth_context,
				      1,
				      &quit_data)) ||
	    (kret = krb5_read_adm_reply(kcontext,
					&conn_socket,
					auth_context,
					&quit_status,
					&quit_ncomps,
					&quit_reply))) {
	    fprintf(stderr, kpwd_proto_error_fmt, argv[0], kpwd_quit_text,
		    error_message(kret));
	    goto done;
	}
	switch (quit_status) {
	case KRB5_ADM_SUCCESS:
	    break;
	case KRB5_ADM_CMD_UNKNOWN:
	    fprintf(stderr, kpwd_pwproto_unsupp_fmt, argv[0], kpwd_quit_text);
	    if (quit_ncomps > 0)
		kpwd_print_sreply(argv[0], quit_ncomps, quit_reply);
	    break;
	default:
	    fprintf(stderr, kpwd_pwproto_error, argv[0],
		    kpwd_reply_to_string(quit_status), kpwd_quit_text);
	    if (quit_ncomps > 0)
		kpwd_print_sreply(argv[0], quit_ncomps, quit_reply);
	}
	krb5_free_adm_data(kcontext, quit_ncomps, quit_reply);
    }

 done:
    krb5_adm_disconnect(kcontext, &conn_socket,	auth_context, ccache);
    krb5_free_context(kcontext);
    return(error);
}
