/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Initialize a credentials cache.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kinit_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <stdio.h>

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>			/* for TGTNAME */
#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>

#include <com_err.h>

#define KRB5_DEFAULT_OPTIONS 0
#define KRB5_DEFAULT_LIFE 60*60*8 /* 8 hours */
#define KRB5_RENEWABLE_LIFE 60*60*2 /* 2 hours */

extern int optind;
extern char *optarg;

krb5_error_code
krb5_parse_lifetime (time, len)
    char *time;
    long *len;
{
    *len = atoi (time) * 60 * 60; /* XXX stub version */
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
    int options = KRB5_DEFAULT_OPTIONS;
    int option;
    int errflg = 0;
    krb5_address **my_addresses;
    krb5_error_code code;
    krb5_principal me;
    krb5_data *server[4];
    krb5_creds my_creds;
    krb5_timestamp now;

    krb5_init_ets();

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    while ((option = getopt(argc, argv, "rpl:c:")) != EOF) {
	switch (option) {
	case 'r':
	    options |= KDC_OPT_RENEWABLE;
	    break;
	case 'p':
	    options |= KDC_OPT_PROXIABLE;
	    break;
	case 'l':
	    code = krb5_parse_lifetime(optarg, &lifetime);
	    if (code != 0) {
		fprintf(stderr, "Bad lifetime value %s\n", optarg);
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
	fprintf(stderr, "Usage: %s [ -rpu ] [ -l lifetime ] [ -c cachename ] principal\n", argv[0]);
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
    my_creds.server = server;

    server[0] = me[0];		/* realm name */
    server[1] = &tgtname;
    server[2] = me[0];
    server[3] = 0;

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
	my_creds.times.renew_till = my_creds.times.starttime +
	    KRB5_RENEWABLE_LIFE;
    } else
	my_creds.times.renew_till = 0;

    code = krb5_get_in_tkt_with_password(options, my_addresses,
					 ETYPE_DES_CBC_CRC,
					 KEYTYPE_DES,
					 0, /* let lib read pwd from kbd */
					 ccache,
					 &my_creds);
    if (code != 0) {
	com_err (argv[0], code, "while getting initial credentials");
	exit(1);
    }
    exit(0);
}
