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
    fprintf(stderr, "xusage: %s [-4 | -e etype] service1 service2 ...\n", prog);
#else
    fprintf(stderr, "xusage: %s [-e etype] service1 service2 ...\n", prog);
#endif
    exit(1);
}

int quiet = 0;

static void do_v4_kvno (int argc, char *argv[]);
static void do_v5_kvno (int argc, char *argv[], char *etypestr);

int main(int argc, char *argv[])
{
    int option;
    char *etypestr = 0;
    int v4 = 0;

    prog = strrchr(argv[0], '/');
    prog = prog ? (prog + 1) : argv[0];

    while ((option = getopt(argc, argv, "e:hq4")) != -1) {
	switch (option) {
	case 'e':
	    etypestr = optarg;
	    break;
	case 'h':
	    xusage();
	    break;
	case 'q':
	    quiet = 1;
	    break;
	case '4':
	    v4 = 1;
	    break;
	default:
	    xusage();
	    break;
	}
    }

    if ((argc - optind) < 1)
	xusage();

    if (etypestr != 0 && v4)
	xusage();

    if (v4)
	do_v4_kvno(argc - optind, argv + optind);
    else
	do_v5_kvno(argc - optind, argv + optind, etypestr);
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
static void do_v5_kvno (int count, char *names[], char *etypestr)
{
    krb5_context context;
    krb5_error_code ret;
    int i, errors;
    krb5_enctype etype;
    krb5_ccache ccache;
    krb5_principal me;
    krb5_creds in_creds, *out_creds;
    krb5_ticket *ticket;
    char *princ;

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

    ret = krb5_cc_default(context, &ccache);
    if (ret) {
	com_err(prog, ret, "while opening ccache");
	exit(1);
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

	ret = krb5_parse_name(context, names[i], &in_creds.server);
	if (ret) {
	    if (!quiet)
		fprintf(stderr, "%s: %s while parsing principal name\n",
			names[i], error_message(ret));
	    errors++;
	    continue;
	}

	ret = krb5_unparse_name(context, in_creds.server, &princ);
	if (ret) {
	    fprintf(stderr, "%s: %s while printing principal name\n",
		    names[i], error_message(ret));
	    errors++;
	    continue;
	}

	in_creds.keyblock.enctype = etype;

	ret = krb5_get_credentials(context, 0, ccache, &in_creds, &out_creds);

	krb5_free_principal(context, in_creds.server);

	if (ret) {
	    fprintf(stderr, "%s: %s while getting credentials\n",
		    princ, error_message(ret));

	    free(princ);

	    errors++;
	    continue;
	}

	/* we need a native ticket */
	ret = krb5_decode_ticket(&out_creds->ticket, &ticket);
	if (ret) {
	    fprintf(stderr, "%s: %s while decoding ticket\n",
		    princ, error_message(ret));

	    krb5_free_creds(context, out_creds);
	    free(princ);

	    errors++;
	    continue;
	}
	    
	if (!quiet)
	    printf("%s: kvno = %d\n", princ, ticket->enc_part.kvno);

	krb5_free_ticket(context, ticket);
	krb5_free_creds(context, out_creds);
	krb5_free_unparsed_name(context, princ);
    }

    krb5_free_principal(context, me);
    krb5_cc_close(context, ccache);
    krb5_free_context(context);

    if (errors)
	exit(1);

    exit(0);
}
