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
#include <string.h>
#include <krb5.h>

extern int optind;
extern char *optarg;

void usage(char *argv0)
{
    char *cmd;

    cmd = strrchr(argv0, '/');
    cmd = cmd?(cmd+1):argv0;

    fprintf(stderr, "usage: %s [-e etype] service1 service2 ...\n", cmd);

    exit(1);
}

int main(int argc, char *argv[])
{
    krb5_context context;
    krb5_error_code ret;
    int option, i, errors;
    char *etypestr = 0;
    int quiet = 0;
    krb5_enctype etype;
    krb5_ccache ccache;
    krb5_principal me;
    krb5_creds in_creds, *out_creds;
    krb5_ticket *ticket;
    char *princ;

    if (ret = krb5_init_context(&context)) {
	com_err(argv[0], ret, "while initializing krb5 library");
	exit(1);
    }

    while ((option = getopt(argc, argv, "e:hq")) != -1) {
	switch (option) {
	case 'e':
	    etypestr = optarg;
	    break;
	case 'h':
	    usage(argv[0]);
	    break;
	case 'q':
	    quiet = 1;
	    break;
	default:
	    usage(argv[0]);
	    break;
	}
    }

    if ((argc - optind) < 1)
	usage(argv[0]);

    if (etypestr) {
	if (ret = krb5_string_to_enctype(etypestr, &etype)) {
	    com_err(argv[0], ret, "while converting etype");
	    exit(1);
	}
    } else {
	etype = 0;
    }

    if (ret = krb5_cc_default(context, &ccache)) {
	com_err(argv[0], ret, "while opening ccache");
	exit(1);
    }

    if (ret = krb5_cc_get_principal(context, ccache, &me)) {
	com_err(argv[0], ret, "while getting client principal name");
	exit(1);
    }

    errors = 0;

    for (i = optind; i < argc; i++) {
	memset(&in_creds, 0, sizeof(in_creds));

	in_creds.client = me;

	if (ret = krb5_parse_name(context, argv[i], &in_creds.server)) {
	    if (!quiet)
		fprintf(stderr, "%s: %s while parsing principal name\n",
			argv[i], error_message(ret));
	    errors++;
	    continue;
	}

	if (ret = krb5_unparse_name(context, in_creds.server, &princ)) {
	    fprintf(stderr, "%s: %s while printing principal name\n",
		    argv[i], error_message(ret));
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
	if (ret = krb5_decode_ticket(&out_creds->ticket, &ticket)) {
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
