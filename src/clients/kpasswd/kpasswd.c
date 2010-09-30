/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <sys/types.h>
#include "autoconf.h"

#ifndef _WIN32
#include <unistd.h>
#endif

#include <krb5.h>

#define P1 "Enter new password"
#define P2 "Enter it again"

#ifdef HAVE_PWD_H
#include <pwd.h>

static
void get_name_from_passwd_file(program_name, kcontext, me)
    char * program_name;
    krb5_context kcontext;
    krb5_principal * me;
{
    struct passwd *pw;
    krb5_error_code code;
    if ((pw = getpwuid(getuid()))) {
        if ((code = krb5_parse_name(kcontext, pw->pw_name, me))) {
            com_err (program_name, code, "when parsing name %s", pw->pw_name);
            exit(1);
        }
    } else {
        fprintf(stderr, "Unable to identify user from password file\n");
        exit(1);
    }
}
#else /* HAVE_PWD_H */
void get_name_from_passwd_file(kcontext, me)
    krb5_context kcontext;
    krb5_principal * me;
{
    fprintf(stderr, "Unable to identify user\n");
    exit(1);
}
#endif /* HAVE_PWD_H */

int main(int argc, char *argv[])
{
    krb5_error_code ret;
    krb5_context context;
    krb5_principal princ = NULL;
    char *pname;
    krb5_ccache ccache;
    krb5_get_init_creds_opt *opts = NULL;
    krb5_creds creds;

    char pw[1024];
    unsigned int pwlen;
    int result_code;
    krb5_data result_code_string, result_string;

    if (argc > 2) {
        fprintf(stderr, "usage: %s [principal]\n", argv[0]);
        exit(1);
    }

    pname = argv[1];

    ret = krb5_init_context(&context);
    if (ret) {
        com_err(argv[0], ret, "initializing kerberos library");
        exit(1);
    }
    if ((ret = krb5_get_init_creds_opt_alloc(context, &opts))) {
        com_err(argv[0], ret, "allocating krb5_get_init_creds_opt");
        exit(1);
    }

    /* in order, use the first of:
       - a name specified on the command line
       - the principal name from an existing ccache
       - the name corresponding to the ruid of the process

       otherwise, it's an error.
       We always attempt to open the default ccache in order to use FAST if
       possible.
    */
    ret = krb5_cc_default(context, &ccache);
    if (ret != 0) {
        com_err(argv[0], ret, "opening default ccache");
        exit(1);
    }
    ret = krb5_cc_get_principal(context, ccache, &princ);
    if (ret != 0 && ret != KRB5_CC_NOTFOUND && ret != KRB5_FCC_NOFILE) {
        com_err(argv[0], ret, "getting principal from ccache");
        exit(1);
    } else {
        if (princ != NULL) {
            ret = krb5_get_init_creds_opt_set_fast_ccache(context, opts,
                                                          ccache);
            if (ret) {
                com_err(argv[0], ret, "while setting FAST ccache");
                exit(1);
            }
        }
    }
    ret = krb5_cc_close(context, ccache);
    if (ret != 0) {
        com_err(argv[0], ret, "closing ccache");
        exit(1);
    }
    if (pname) {
        krb5_free_principal(context, princ);
        princ = NULL;
        if ((ret = krb5_parse_name(context, pname, &princ))) {
            com_err(argv[0], ret, "parsing client name");
            exit(1);
        }
    }
    if (princ == NULL)
        get_name_from_passwd_file(argv[0], context, &princ);

    krb5_get_init_creds_opt_set_tkt_life(opts, 5*60);
    krb5_get_init_creds_opt_set_renew_life(opts, 0);
    krb5_get_init_creds_opt_set_forwardable(opts, 0);
    krb5_get_init_creds_opt_set_proxiable(opts, 0);

    if ((ret = krb5_get_init_creds_password(context, &creds, princ, NULL,
                                            krb5_prompter_posix, NULL,
                                            0, "kadmin/changepw", opts))) {
        if (ret == KRB5KRB_AP_ERR_BAD_INTEGRITY)
            com_err(argv[0], 0,
                    "Password incorrect while getting initial ticket");
        else
            com_err(argv[0], ret, "getting initial ticket");
        krb5_get_init_creds_opt_free(context, opts);
        exit(1);
    }

    pwlen = sizeof(pw);
    if ((ret = krb5_read_password(context, P1, P2, pw, &pwlen))) {
        com_err(argv[0], ret, "while reading password");
        krb5_get_init_creds_opt_free(context, opts);
        exit(1);
    }

    if ((ret = krb5_change_password(context, &creds, pw,
                                    &result_code, &result_code_string,
                                    &result_string))) {
        com_err(argv[0], ret, "changing password");
        krb5_get_init_creds_opt_free(context, opts);
        exit(1);
    }

    if (result_code) {
        printf("%.*s%s%.*s\n",
               (int) result_code_string.length, result_code_string.data,
               result_string.length?": ":"",
               (int) result_string.length,
               result_string.data ? result_string.data : "");
        krb5_get_init_creds_opt_free(context, opts);
        exit(2);
    }

    if (result_string.data != NULL)
        free(result_string.data);
    if (result_code_string.data != NULL)
        free(result_code_string.data);
    krb5_get_init_creds_opt_free(context, opts);

    printf("Password changed.\n");
    exit(0);
}
