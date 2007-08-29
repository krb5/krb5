/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include "autoconf.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>

extern int optind;
extern char *optarg;

static char *prog;

static void xusage()
{
#ifdef KRB5_KRB4_COMPAT
    fprintf(stderr, 
            "usage: %s [-4 | [-c ccache] [-e etype] [-k keytab] [-S sname]] service1 service2 ...\n", 
            prog);
#else
    fprintf(stderr, "usage: %s [-c ccache] [-e etype] [-k keytab] [-S sname] service1 service2 ...\n",
            prog);
#endif
    exit(1);
}

int quiet = 0;

static void do_v4_kvno (int argc, char *argv[]);
static void do_v5_kvno (int argc, char *argv[], 
                        char *ccachestr, char *etypestr, char *keytab_name,
			char *sname);

#include <com_err.h>
static void extended_com_err_fn (const char *, errcode_t, const char *,
				 va_list);

int main(int argc, char *argv[])
{
    int option;
    char *etypestr = NULL, *ccachestr = NULL, *keytab_name = NULL;
    char *sname = NULL;
    int v4 = 0;

    set_com_err_hook (extended_com_err_fn);

    prog = strrchr(argv[0], '/');
    prog = prog ? (prog + 1) : argv[0];

    while ((option = getopt(argc, argv, "c:e:hk:q4S:")) != -1) {
	switch (option) {
	case 'c':
	    ccachestr = optarg;
	    break;
	case 'e':
	    etypestr = optarg;
	    break;
	case 'h':
	    xusage();
	    break;
	case 'k':
	    keytab_name = optarg;
	    break;
	case 'q':
	    quiet = 1;
	    break;
	case '4':
	    v4 = 1;
	    break;
	case 'S':
	    sname = optarg;
	    break;
	default:
	    xusage();
	    break;
	}
    }

    if ((argc - optind) < 1)
	xusage();

    if ((ccachestr != NULL || etypestr != NULL || keytab_name != NULL) && v4)
	xusage();

    if (sname != NULL && v4)
	xusage();

    if (v4)
	do_v4_kvno(argc - optind, argv + optind);
    else
	do_v5_kvno(argc - optind, argv + optind,
		   ccachestr, etypestr, keytab_name, sname);
    return 0;
}

#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#endif
static void do_v4_kvno (int count, char *names[])
{
#ifdef KRB5_KRB4_COMPAT
    int i;

    for (i = 0; i < count; i++) {
	int err;
	char name[ANAME_SZ], inst[INST_SZ], realm[REALM_SZ];
	KTEXT_ST req;
	CREDENTIALS creds;
	*name = *inst = *realm = '\0';
	err = kname_parse (name, inst, realm, names[i]);
	if (err) {
	    fprintf(stderr, "%s: error parsing name '%s': %s\n",
		    prog, names[i], krb_get_err_text(err));
	    exit(1);
	}
	if (realm[0] == 0) {
	    err = krb_get_lrealm(realm, 1);
	    if (err) {
		fprintf(stderr, "%s: error looking up local realm: %s\n",
			prog, krb_get_err_text(err));
		exit(1);
	    }
	}
	err = krb_mk_req(&req, name, inst, realm, 0);
	if (err) {
	    fprintf(stderr, "%s: krb_mk_req error: %s\n", prog,
		    krb_get_err_text(err));
	    exit(1);
	}
	err = krb_get_cred(name, inst, realm, &creds);
	if (err) {
	    fprintf(stderr, "%s: krb_get_cred error: %s\n", prog,
		    krb_get_err_text(err));
	    exit(1);
	}
	if (!quiet)
	    printf("%s: kvno = %d\n", names[i], creds.kvno);
    }
#else
    xusage();
#endif
}

#include <krb5.h>
static krb5_context context;
static void extended_com_err_fn (const char *myprog, errcode_t code,
				 const char *fmt, va_list args)
{
    const char *emsg;
    emsg = krb5_get_error_message (context, code);
    fprintf (stderr, "%s: %s ", myprog, emsg);
    krb5_free_error_message (context, emsg);
    vfprintf (stderr, fmt, args);
    fprintf (stderr, "\n");
}

static void do_v5_kvno (int count, char *names[], 
                        char * ccachestr, char *etypestr, char *keytab_name,
			char *sname)
{
    krb5_error_code ret;
    int i, errors;
    krb5_enctype etype;
    krb5_ccache ccache;
    krb5_principal me;
    krb5_creds in_creds, *out_creds;
    krb5_ticket *ticket;
    char *princ;
    krb5_keytab keytab = NULL;

    ret = krb5_init_context(&context);
    if (ret) {
	com_err(prog, ret, "while initializing krb5 library");
	exit(1);
    }

    if (etypestr) {
        ret = krb5_string_to_enctype(etypestr, &etype);
	if (ret) {
	    com_err(prog, ret, "while converting etype");
	    exit(1);
	}
    } else {
	etype = 0;
    }

    if (ccachestr)
        ret = krb5_cc_resolve(context, ccachestr, &ccache);
    else
        ret = krb5_cc_default(context, &ccache);
    if (ret) {
	com_err(prog, ret, "while opening ccache");
	exit(1);
    }

    if (keytab_name) {
	ret = krb5_kt_resolve(context, keytab_name, &keytab);
	if (ret) {
	    com_err(prog, ret, "resolving keytab %s", keytab_name);
	    exit(1);
	}
    }

    ret = krb5_cc_get_principal(context, ccache, &me);
    if (ret) {
	com_err(prog, ret, "while getting client principal name");
	exit(1);
    }

    errors = 0;

    for (i = 0; i < count; i++) {
	memset(&in_creds, 0, sizeof(in_creds));

	in_creds.client = me;

	if (sname != NULL) {
	    ret = krb5_sname_to_principal(context, names[i],
					  sname, KRB5_NT_SRV_HST,
					  &in_creds.server);
	} else {
	    ret = krb5_parse_name(context, names[i], &in_creds.server);
	}
	if (ret) {
	    if (!quiet)
		com_err(prog, ret, "while parsing principal name %s", names[i]);
	    errors++;
	    continue;
	}

	ret = krb5_unparse_name(context, in_creds.server, &princ);
	if (ret) {
	    com_err(prog, ret,
		    "while formatting parsed principal name for '%s'",
		    names[i]);
	    errors++;
	    continue;
	}

	in_creds.keyblock.enctype = etype;

	ret = krb5_get_credentials(context, 0, ccache, &in_creds, &out_creds);

	krb5_free_principal(context, in_creds.server);

	if (ret) {
	    com_err(prog, ret, "while getting credentials for %s", princ);

	    krb5_free_unparsed_name(context, princ);

	    errors++;
	    continue;
	}

	/* we need a native ticket */
	ret = krb5_decode_ticket(&out_creds->ticket, &ticket);
	if (ret) {
	    com_err(prog, ret, "while decoding ticket for %s", princ);
	    krb5_free_creds(context, out_creds);
	    krb5_free_unparsed_name(context, princ);

	    errors++;
	    continue;
	}
	    
	if (keytab) {
	    ret = krb5_server_decrypt_ticket_keytab(context, keytab, ticket);
	    if (ret) {
		if (!quiet)
		    printf("%s: kvno = %d, keytab entry invalid", princ, ticket->enc_part.kvno);
		com_err(prog, ret, "while decrypting ticket for %s", princ);
		krb5_free_ticket(context, ticket);
		krb5_free_creds(context, out_creds);
		krb5_free_unparsed_name(context, princ);

		errors++;
		continue;
	    }
	    if (!quiet)
		printf("%s: kvno = %d, keytab entry valid\n", princ, ticket->enc_part.kvno);
	} else {
	    if (!quiet)
		printf("%s: kvno = %d\n", princ, ticket->enc_part.kvno);
	}

	krb5_free_creds(context, out_creds);
	krb5_free_unparsed_name(context, princ);
    }

    if (keytab)
	krb5_kt_close(context, keytab);
    krb5_free_principal(context, me);
    krb5_cc_close(context, ccache);
    krb5_free_context(context);

    if (errors)
	exit(1);

    exit(0);
}
