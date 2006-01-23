/*
 * Generic error handling is defined here.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <k5-thread.h>
#include "com_err.h"
#include "err_handle.h"
#include "k5-int.h"

MAKE_INIT_FUNCTION(init_kdb_err);

static int init_kdb_err(void) {
    int err;
    static int called = 0;

    /* Safety check. Should not be required ... */
    if (called == 1)
	return 0;

    err = k5_key_register(K5_KEY_KDB_ERR_STR, free);

    assert(err == 0);

    called = 1;

    return 0;
}

void krb5_kdb_set_err_str (char *str){
    int ret, new = 0;;
    char *err;

    CALL_INIT_FUNCTION (init_kdb_err);

    err = (char *) k5_getspecific (K5_KEY_KDB_ERR_STR);

    if (err == NULL) {
	err = (char *)malloc(KRB5_MAX_ERR_STR);
	assert(err != NULL);
	err[KRB5_MAX_ERR_STR - 1] = '\0';
	new = 1;
    }

    strncpy (err, str, KRB5_MAX_ERR_STR - 1);

    if (new == 1) {
	ret = k5_setspecific (K5_KEY_KDB_ERR_STR, err);
	assert (ret == 0);
    }
}

void krb5_kdb_get_err_str (char *str, int len){
    char *err;

    CALL_INIT_FUNCTION (init_kdb_err);

    err = (char *) k5_getspecific (K5_KEY_KDB_ERR_STR);
    if (err == NULL) {
	str[0] = '\0';
	return;
    }

    strncpy (str, err, (unsigned int)len);
    str[len - 1] = '\0';

    /* The error will be cleared after the first invocation */
    err[0] = '\0';
}

void krb5_kdb_clear_err_str (){
    CALL_INIT_FUNCTION (init_kdb_err);

    krb5_kdb_set_err_str ("");
}

void krb5_kdb_prepend_err_str (char *str) {
    char err[KRB5_MAX_ERR_STR], new_err[KRB5_MAX_ERR_STR];

    CALL_INIT_FUNCTION (init_kdb_err);

    krb5_kdb_get_err_str (err, KRB5_MAX_ERR_STR);

    snprintf (new_err, sizeof(new_err), "%s%s", str, err);
    new_err[sizeof (new_err)] = '\0';

    krb5_kdb_set_err_str (new_err);
}

void new_default_com_err_proc (const char *whoami, errcode_t code,
				  const char *fmt, va_list ap)
{
    char errbuf[KRB5_MAX_ERR_STR + 1];

    CALL_INIT_FUNCTION (init_kdb_err);

    if (whoami) {
	fputs(whoami, stderr);
	fputs(": ", stderr);
    }
    if (code) {
	error_message_w (code, errbuf, sizeof(errbuf));
	fputs(errbuf, stderr);
	fputs(" ", stderr);
    }
    if (fmt) {
	vfprintf(stderr, fmt, ap);
    }
    /* should do this only on a tty in raw mode */
    putc('\r', stderr);
    putc('\n', stderr);
    fflush(stderr);
}
