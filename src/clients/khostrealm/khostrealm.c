/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2016 by Rick van Rein, for ARPA2.net and SURFnet
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

#include "k5-platform.h"
#include <locale.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>
#include <stdio.h>

#include <krb5.h>


/* Lookup the realm for each host name.  Report the result on a line for each
 * host, with an empty line when no result was found.  When not all results
 * are found, the exit code is 1, otherwise it is 0.
 *
 * When multiple realms are found for one host, then they are printed with
 * spaces to separate them, on the same line.
 *
 * The -f flag switches to the fallback variant of the hostrealm API.
 */
int main (int argc, char *argv []) {
	int argi = 1;
	int fallback = 0;
	int usage = 0;
	int exitval = 0;
	char **realmlist = NULL;
	int rlmi =0;
	krb5_context ctx;
	krb5_error_code kerrno;
	krb5_data hdata;
	//
	// Check arguments
	if ((argi < argc) && (strcmp (argv [argi], "-f") == 0)) {
		fallback = 1;
		argi++;
	}
	if (argi < argc) {
		if (strcmp (argv [argi], "--") == 0) {
			argi++;
		} else if (*argv [argi] == '-') {
			usage = 1;
		}
	}
	if (argi >= argc) {
		usage = 1;
	}
	if (usage) {
		fprintf (stderr, "Usage: %s [-f] [--] host...\n", argv [0]);
		exit (1);
	}
	//
	// Open the libkrb5 context
	if (krb5_init_context (&ctx) != 0) {
		fprintf (stderr, "Failed to open Kerberos context\n");
		exit (1);
	};
	//
	// Perform a hostrealm lookup for each hostname
	while (argi < argc) {
		if (fallback) {
			hdata.data = argv [argi];
			hdata.length = strlen (argv [argi]);
			kerrno = krb5_get_fallback_host_realm (ctx, &hdata, &realmlist);
		} else {
			kerrno = krb5_get_host_realm (ctx, argv [argi], &realmlist);
		}
		if (kerrno == 0) {
			if (*realmlist == NULL) {
				exitval = 1;
			} else if (strcmp (*realmlist, KRB5_REFERRAL_REALM) == 0) {
				exitval = 1;
			} else {
				rlmi = 0;
				while (realmlist [rlmi] != NULL) {
					printf ("%s%s",
						(rlmi > 0)? " ": "",
						realmlist [rlmi]);
					rlmi++;
				}
			}
			krb5_free_host_realm (ctx, realmlist);
		} else {
			exitval = 1;
		}
		putchar ('\n');
		fflush (stdout);
		realmlist = NULL;
		rlmi = 0;
		argi++;
	}
	//
	// Cleanup and close down
	fflush (stdout);
	krb5_free_context (ctx);
	exit (exitval);
}
