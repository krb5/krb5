/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 *
 * Initialize a credentials cache.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kinit_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <stdio.h>

#include <krb5/krb5.h>
#include <krb5/kdb.h>			/* for TGTNAME */
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>

#include <com_err.h>

#define KRB5_DEFAULT_OPTIONS 0
#define KRB5_DEFAULT_LIFE 60*60*8 /* 8 hours */

extern int optind;
extern char *optarg;

krb5_error_code
krb5_parse_lifetime (time, len)
    char *time;
    long *len;
{
    *len = convtime(time);
    return 0;
}
    
krb5_data tgtname = {
    sizeof(TGTNAME)-1,
    TGTNAME
};

void
main(argc, argv)
    int argc;
    char **argv;
{
    krb5_ccache ccache = NULL;
    char *cache_name = NULL;		/* -f option */
    long lifetime = KRB5_DEFAULT_LIFE;	/* -l option */
    long rlife = 0;
    int options = KRB5_DEFAULT_OPTIONS;
    int option;
    int errflg = 0;
    krb5_address **my_addresses;
    krb5_error_code code;
    krb5_principal me;
    krb5_principal server;
    krb5_creds my_creds;
    krb5_timestamp now;

    krb5_init_ets();

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    while ((option = getopt(argc, argv, "r:fpl:c:")) != EOF) {
	switch (option) {
	case 'r':
	    options |= KDC_OPT_RENEWABLE;
	    code = krb5_parse_lifetime(optarg, &rlife);
	    if (code != 0 || rlife == 0) {
		fprintf(stderr, "Bad lifetime value (%s hours?)\n", optarg);
		errflg++;
	    }
	    break;
	case 'p':
	    options |= KDC_OPT_PROXIABLE;
	    break;
	case 'f':
	    options |= KDC_OPT_FORWARDABLE;
	    break;
	case 'l':
	    code = krb5_parse_lifetime(optarg, &lifetime);
	    if (code != 0 || lifetime == 0) {
		fprintf(stderr, "Bad lifetime value (%s hours?\n", optarg);
		errflg++;
	    }
	    break;
	case 'c':
	    if (ccache == NULL) {
		cache_name = optarg;
		
		code = krb5_cc_resolve (cache_name, &ccache);
		if (code != 0) {
		    com_err (argv[0], code, "resolving %s", cache_name);
		    errflg++;
		}
	    } else {
		fprintf(stderr, "Only one -c option allowed\n");
		errflg++;
	    }
	    break;
	case '?':
	default:
	    errflg++;
	    break;
	}
    }
    if (optind != argc-1)
	errflg++;
    
    if (errflg) {
	fprintf(stderr, "Usage: %s [ -r time ] [ -puf ] [ -l lifetime ] [ -c cachename ] principal\n", argv[0]);
	exit(2);
    }
    if (ccache == NULL) {
	if (code = krb5_cc_default(&ccache)) {
	    com_err(argv[0], code, "while getting default ccache");
	    exit(1);
	}
    }
    if (code = krb5_parse_name (argv[optind], &me)) {
	com_err (argv[0], code, "when parsing name %s",argv[optind]);
	exit(1);
    }

    code = krb5_cc_initialize (ccache, me);
    if (code != 0) {
	com_err (argv[0], code, "when initializing cache %s",
		 cache_name?cache_name:"");
	exit(1);
    }

    memset((char *)&my_creds, 0, sizeof(my_creds));
    
    my_creds.client = me;

    if (code = krb5_build_principal_ext(&server,
					me[0]->length, me[0]->data,
					tgtname.length, tgtname.data,
					me[0]->length, me[0]->data,
					0)) {
	com_err(argv[0], code, "while building server name");
	exit(1);
    }

    my_creds.server = server;

    code = krb5_os_localaddr(&my_addresses);
    if (code != 0) {
	com_err (argv[0], code, "when getting my address");
	exit(1);
    }
    if (code = krb5_timeofday(&now)) {
	com_err(argv[0], code, "while getting time of day");
	exit(1);
    }
    my_creds.times.starttime = 0;	/* start timer when request
					   gets to KDC */
    my_creds.times.endtime = now + lifetime;
    if (options & KDC_OPT_RENEWABLE) {
	my_creds.times.renew_till = now + rlife;
    } else
	my_creds.times.renew_till = 0;

    code = krb5_get_in_tkt_with_password(options, my_addresses,
					 ETYPE_DES_CBC_CRC,
					 KEYTYPE_DES,
					 0, /* let lib read pwd from kbd */
					 ccache,
					 &my_creds);
    krb5_free_principal(server);
    if (code != 0) {
	com_err (argv[0], code, "while getting initial credentials");
	exit(1);
    }
    exit(0);
}

/*
 * this next function was lifted from the source to sendmail, which is:
 * 
 * Copyright (c) 1983 Eric P. Allman
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted provided
 * that: (1) source distributions retain this entire copyright notice and
 * comment, and (2) distributions including binaries display the following
 * acknowledgement:  ``This product includes software developed by the
 * University of California, Berkeley and its contributors'' in the
 * documentation or other materials provided with the distribution and in
 * all advertising materials mentioning features or use of this software.
 * Neither the name of the University nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

time_t
convtime(p)
        char *p;
{
        register time_t t, r;
        register char c;

        r = 0;
        while (*p != '\0')
        {
                t = 0;
                while (isdigit(c = *p++))
                        t = t * 10 + (c - '0');
                if (c == '\0')
                        p--;
                switch (c)
                {
                  case 'w':             /* weeks */
                        t *= 7;

                  case 'd':             /* days */
                        t *= 24;

                  case 'h':             /* hours */
                  default:
                        t *= 60;

                  case 'm':             /* minutes */
                        t *= 60;

                  case 's':             /* seconds */
                        break;
                }
                r += t;
        }

        return (r);
}

