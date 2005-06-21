/**********************************************************************
*
*	C %name:		err_handle.c %
*	Instance:		idc_sec_1
*	Description:	
*	%created_by:	spradeep %
*	%date_created:	Thu Apr  7 15:36:27 2005 %
*
**********************************************************************/
#ifndef lint
static char *_csrc =
    "@(#) %filespec: err_handle.c~1 %  (%full_filespec: err_handle.c~1:csrc:idc_sec#2 %)";
#endif

/* This file should be ideally be in util/et.  But, for now thread
   safety requirement stops me from putting there.  If I do, then all
   the applications have to link to pthread.  */

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#include "err_handle.h"
#include <assert.h>

#ifdef NOVELL
krb5_errcode_2_string_func old_error_2_string = NULL;
#endif

typedef struct
{
    char    krb5_err_str[KRB5_MAX_ERR_STR + 1];
    long    err_code;
    krb5_err_subsystem subsystem;
    krb5_context kcontext;
} krb5_err_struct_t;

#ifdef HAVE_PTHREAD_H
static void
tsd_key_destructor(void *data)
{
    free(data);
}

static pthread_key_t krb5_err_key;

static void
init_err_handling(void)
{
    assert(!pthread_key_create(&krb5_err_key, tsd_key_destructor));
#ifdef NOVELL
    old_error_2_string = error_message;
    error_message = krb5_get_err_string;
#endif
}

static pthread_once_t krb5_key_create = PTHREAD_ONCE_INIT;

krb5_error_code
krb5_set_err(krb5_context kcontext, krb5_err_subsystem subsystem,
	     long err_code, char *str)
{
    int     ret;
    krb5_err_struct_t *err_struct;
    pthread_once(&krb5_key_create, init_err_handling);

    err_struct = (krb5_err_struct_t *) pthread_getspecific(krb5_err_key);
    if (err_struct == NULL) {
	err_struct = calloc(sizeof(krb5_err_struct_t), 1);
	if (err_struct == NULL)
	    return ENOMEM;

	if ((ret = pthread_setspecific(krb5_err_key, err_struct))) {
	    free(err_struct);
	    return ret;
	}
    }

    err_struct->subsystem = subsystem;
    err_struct->err_code = err_code;
    err_struct->kcontext = kcontext;
    if (err_struct->subsystem == krb5_err_have_str) {
	strncpy(err_struct->krb5_err_str, str,
		sizeof(err_struct->krb5_err_str));
	err_struct->krb5_err_str[KRB5_MAX_ERR_STR] = '\0';
    }

    return 0;
}

const char *KRB5_CALLCONV
krb5_get_err_string(long err_code)
{
    krb5_err_struct_t *err_struct;
    pthread_once(&krb5_key_create, init_err_handling);

    err_struct = (krb5_err_struct_t *) pthread_getspecific(krb5_err_key);
    if (err_struct && (err_struct->subsystem == krb5_err_have_str)
	&& (err_code == err_struct->err_code)) {
	/* checking error code is for safety.
	   In case, the caller ignores a database error and calls
	   other calls before doing com_err.  Though not perfect,
	   caller should call krb5_clr_error before this.  */
	err_struct->subsystem = krb5_err_unknown;
	return err_struct->krb5_err_str;
    }

    /* Error strings are not generated here. the remaining two cases
       are handled by the default error string convertor.  */
#ifdef NOVELL
    return old_error_2_string(err_code);
#else
    return error_message(err_code);
#endif
}

void
krb5_clr_error()
{
    krb5_err_struct_t *err_struct;
    pthread_once(&krb5_key_create, init_err_handling);

    err_struct = (krb5_err_struct_t *) pthread_getspecific(krb5_err_key);
    if (err_struct)
	err_struct->subsystem = krb5_err_unknown;
}

#else
krb5_err_struct_t krb5_err = { {0}, 0, 0, 0 };
krb5_boolean krb5_init_once = TRUE;

static void
init_err_handling(void)
{
    if (krb5_init_once) {
#ifdef NOVELL
	old_error_2_string = error_message;
	error_message = krb5_get_err_string;
#endif
	krb5_init_once = FALSE;
    }
}

krb5_error_code
krb5_set_err(krb5_context kcontext, krb5_err_subsystem subsystem,
	     long err_code, char *str)
{
    krb5_err_struct_t *err_struct = &krb5_err;

    init_err_handling();	/* takes care for multiple inits */

    err_struct->subsystem = subsystem;
    err_struct->err_code = err_code;
    err_struct->kcontext = kcontext;
    if (err_struct->subsystem == krb5_err_have_str) {
	strncpy(err_struct->krb5_err_str, str,
		sizeof(err_struct->krb5_err_str));
	err_struct->krb5_err_str[KRB5_MAX_ERR_STR] = '\0';
    }

    return 0;
}

const char *KRB5_CALLCONV
krb5_get_err_string(long err_code)
{
    krb5_err_struct_t *err_struct = &krb5_err;

    init_err_handling();	/* takes care for multiple inits */

    if ((err_struct->subsystem == krb5_err_have_str)
	&& (err_code == err_struct->err_code)) {
	/* checking error code is for safety.
	   In case, the caller ignores a database error and calls
	   other calls before doing com_err.  Though not perfect,
	   caller should call krb5_clr_error before this.  */
	err_struct->subsystem = krb5_err_unknown;
	return err_struct->krb5_err_str;
    }

    /* It is not generated here. the remaining two cases are handled
       by the default error string convertor.  */
#ifdef NOVELL
    return old_error_2_string(err_code);
#else
    return error_message(err_code);
#endif
}

void
krb5_clr_error()
{
    krb5_err_struct_t *err_struct = &krb5_err;

    init_err_handling();	/* takes care for multiple inits */

    err_struct->subsystem = krb5_err_unknown;
}

#endif
