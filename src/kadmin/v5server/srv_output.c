/*
 * kadmin/v5server/srv_output.c
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * srv_output.c - Handle Kerberos output related functions.
 */
#include "k5-int.h"
#include "com_err.h"
#include "kadm5_defs.h"
#include "adm.h"

static const char *out_adm_success = "Operation successful.";
static const char *out_adm_cmd_unknown = "Command %s unknown.";
static const char *out_adm_pw_unaccept = "Password unacceptable.";
static const char *out_adm_bad_princ = "Principal unknown.";
static const char *out_adm_pwd_too_short = "Password is too short.";
static const char *out_adm_pwd_weak = "Password generates weak key.";
static const char *out_adm_not_allowed = "You are not allowed to change your password.";
static const char *out_adm_bad_pw = "Password incorrect.";
static const char *out_adm_not_in_tkt = "Not an initial ticket.";
static const char *out_adm_cant_change = "Cannot change password.";
static const char *out_adm_lang_unsupp = "Language %s unsupported.";
static const char *out_adm_bad_args = "Bad argument list format for %s command.";
static const char *out_adm_bad_cmd = "Command %s not supported.";
static const char *out_adm_no_cmd = "No command in message.";
static const char *out_adm_no_err = "Unknown error.";
static int output_debug_level = 0;
static int output_mime_enabled = 0;

static char *
lang_error_message(lang, kval)
    char		*lang;
    krb5_error_code	kval;
{
    char	*ret;
    char	*ermsg;

    ermsg = error_message(kval);
    if (lang && output_lang_supported(lang)) {
	/*
	 * Just for demonstration purposes.
	 */
	ret = (char *) malloc(strlen(ermsg)+strlen(lang)+3+1);
	if (ret)
	    sprintf(ret, "%s - %s", lang, ermsg);
    }
    else {
	ret = (char *) malloc(strlen(ermsg)+1);
	if (ret)
	    strcpy(ret, ermsg);
    }
    return(ret);
}

static char *
lang_adm_message(lang, ecode, aux, nargs, alist)
    char		*lang;
    krb5_int32		ecode;
    krb5_int32		aux;
    krb5_int32		nargs;
    krb5_data		*alist;
{
    char	*ret;
    const char	*ermsg;
    char	*erarg;
    int		alen;

    erarg = (char *) NULL;
    switch (ecode) {
    case KRB5_ADM_SUCCESS:
	ermsg = out_adm_success; break;
    case KRB5_ADM_CMD_UNKNOWN:
	switch (aux) {
	case KRB5_ADM_BAD_ARGS:
	    ermsg = out_adm_bad_args;
	    erarg = ((nargs >= 1) ? alist[0].data : (char *) NULL);
	    break;
	case KRB5_ADM_BAD_CMD:
	    ermsg = out_adm_bad_cmd;
	    erarg = ((nargs >= 1) ? alist[0].data : (char *) NULL);
	    break;
	case KRB5_ADM_NO_CMD:
	    ermsg = out_adm_no_cmd;
	    break;
	default:
	    ermsg = out_adm_bad_args;
	    erarg = ((nargs >= 1) ? alist[0].data : (char *) NULL);
	    break;
	}
	break;
    case KRB5_ADM_PW_UNACCEPT:
	switch (aux) {
	case KRB5_ADM_BAD_PRINC:
	    ermsg = out_adm_bad_princ;
	    break;
	case KRB5_ADM_PWD_TOO_SHORT:
	    ermsg = out_adm_pwd_too_short;
	    break;
	case KRB5_ADM_PWD_WEAK:
	    ermsg = out_adm_pwd_weak;
	    break;
	default:
	    ermsg = out_adm_pw_unaccept;
	    break;
	}
	break;
    case KRB5_ADM_BAD_PW:
	ermsg = out_adm_bad_pw; break;
    case KRB5_ADM_NOT_IN_TKT:
	ermsg = out_adm_not_in_tkt; break;
    case KRB5_ADM_CANT_CHANGE:
	switch (aux) {
	case KRB5_ADM_BAD_PRINC:
	    ermsg = out_adm_bad_princ;
	    break;
	case KRB5_ADM_PWD_TOO_SHORT:
	    ermsg = out_adm_pwd_too_short;
	    break;
	case KRB5_ADM_PWD_WEAK:
	    ermsg = out_adm_pwd_weak;
	    break;
	case KRB5_ADM_NOT_ALLOWED:
	    ermsg = out_adm_not_allowed;
	    break;
	default:
	    ermsg = out_adm_cant_change;
	    break;
	}
	break;
    case KRB5_ADM_LANG_NOT_SUPPORTED:
	ermsg = out_adm_lang_unsupp;
	erarg = ((nargs >= 2) ? alist[1].data : (char *) NULL);
	break;
    default:
	ermsg = out_adm_no_err; break;
    }

    alen = strlen(ermsg)+1;
    if (erarg)
	alen += strlen(erarg);
    if (lang && output_lang_supported(lang)) {
	alen += strlen(lang)+3;
    }
    ret = (char *) malloc(alen);
    if (lang && output_lang_supported(lang)) {
	char *xxx;

	/*
	 * Just for demonstration purposes.
	 */
	if (ret) {
	    sprintf(ret, "%s - ", lang);
	    xxx = &ret[strlen(ret)];
	    sprintf(xxx, ermsg, erarg);
	}
    }
    else {
	if (ret)
	    sprintf(ret, ermsg, erarg);
    }
    return(ret);
}

static char *
mimeify_text(msg)
    char *msg;
{
    char *ret;
    /*
     * Just for demonstration purposes.
     */

    if (output_mime_enabled) {
	ret = (char *) malloc(strlen(msg)+6+3);
	if (ret)
	    sprintf(ret, "MIME: %s\r\n", msg);
	if (!ret)
	    ret = msg;
    }
    else
	ret = msg;
    return(ret);
}

/*
 * output_init()	- Initialize output context.
 */
krb5_error_code
output_init(kcontext, debug_level, language_list, mime_enabled)
    krb5_context	kcontext;
    int			debug_level;
    char		*language_list;
    krb5_boolean	mime_enabled;
{
    krb5_error_code	kret;

    kret = 0;
    output_debug_level = debug_level;
    DPRINT(DEBUG_CALLS, output_debug_level,
	   ("* output_init(llist=%s, mime=%d)\n",
	    ((language_list) ? language_list : "(null)"),
	    mime_enabled));
    output_mime_enabled = mime_enabled;
    DPRINT(DEBUG_CALLS, output_debug_level, ("X output_init() = %d\n", kret));
    return(kret);
}

/*
 * output_finish	- Terminate output context.
 */
void
output_finish(kcontext, debug_level)
    krb5_context	kcontext;
    int			debug_level;
{
    DPRINT(DEBUG_CALLS, output_debug_level, ("* output_finish()\n"));
    DPRINT(DEBUG_CALLS, output_debug_level, ("X output_finish()\n"));
}

/*
 * output_lang_supported- Is a language supported?
 */
krb5_boolean
output_lang_supported(lname)
    char		*lname;
{
    krb5_boolean	ret;
    DPRINT(DEBUG_CALLS, output_debug_level,
	   ("* output_lang_supported(lang=%s)\n",
	    ((lname) ? lname : "(default)")));
    ret = 1;
    DPRINT(DEBUG_CALLS, output_debug_level,
	   ("X output_lang_supported() = %d\n", ret));
    return(ret);
}

/*
 * output_errmsg	- Return an error message.
 */
char *
output_krb5_errmsg(lang, mime, kval)
    char *		lang;
    krb5_boolean	mime;
    krb5_error_code	kval;
{
    char *ret;
    char *ermsg;
    int alen;

    DPRINT(DEBUG_CALLS, output_debug_level,
	   ("* output_krb5_errmsg(v=%d, lang=%s, mime=%d)\n",
	    kval, ((lang) ? lang : "(default)", mime)));
    ermsg = lang_error_message(lang, kval);
    if (mime) {
	ret = mimeify_text(ermsg);
	if (ret != ermsg)
	    free(ermsg);
    }
    else
	ret = ermsg;
    DPRINT(DEBUG_CALLS, output_debug_level, ("X output_krb5_errmsg()\n"));
    return(ret);
}

/*
 * output_adm_error	- Output an administrative error message string.
 */
char *
output_adm_error(lang, mime, ecode, aux, nargs, alist)
    char		*lang;
    krb5_boolean	mime;
    krb5_int32		ecode;
    krb5_int32		aux;
    krb5_int32		nargs;
    krb5_data		*alist;
{
    char		*ermsg;
    char		*ret;

    DPRINT(DEBUG_CALLS, output_debug_level,
	   ("* output_adm_err(lang=%s, mime=%d, code=%d/%d)\n",
	    ((lang) ? lang : "(default)"), mime, ecode, aux));
    ermsg = lang_adm_message(lang, ecode, aux, nargs, alist);
    if (mime) {
	ret = mimeify_text(ermsg);
	if (ret != ermsg)
	    free(ermsg);
    }
    else
	ret = ermsg;
    DPRINT(DEBUG_CALLS, output_debug_level, ("X output_adm_err()\n"));
    return(ret);
}
