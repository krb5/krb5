/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
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

#define KRB5_DEFAULT_FLAGS 0
#define KRB5_DEFAULT_LIFE 60*60*8 /* 8 hours */

extern int optind;
extern char *optarg;

krb5_parse_lifetime (time, len)
    char *time;
    long *len;
{
    *len = atoi (time) * 60 * 60; /* XXX stub version */
}
    

main(argc, argv)
    int argc;
    char **argv;
{
    krb5_ccache cache = NULL;
    char *cache_name = NULL;		/* -f option */
    long lifetime = KRB5_DEFAULT_LIFE;	/* -l option */
    int flags = KRB5_DEFAULT_FLAGS;
    int option;
    int errflg = 0;
    krb5_address **my_addresses;
    int code;
    krb5_principal me;
    
    /*
     * XXX init error tables here
     */
    while ((option = getopt(argc, argv, "rpl:c:")) != EOF) {
	switch (option) {
	case 'r':
	    flags |= KDC_OPT_RENEWABLE;
	    break;
	case 'p':
	    flags |= KDC_OPT_PROXIABLE;
	    break;
	case 'l':
	    code = krb5_parse_lifetime(optarg, &lifetime);
	    if (code != 0) {
		fprintf(stderr, "Bad lifetime value %s\n", optarg);
		errflg++;
	    }
	    break;
	case 'c':
	    if (cache == NULL) {
		cache_name = optarg;
		
		code = krb5_cc_resolve (cache_name, &cache);
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
	fprintf(stderr, "Usage: %s [ -rp ] [ -l lifetime ] [ -c cachename ] principal", argv[0]);
	exit(2);
    }
    if (cache == NULL)
	cache = krb5_cc_default();

    krb5_parse_name (argv[optind], &me);

    code = krb5_cc_initialize (cache, me);
    if (code != 0) {
	com_err (argv[0], code, "when initializing cache %s",
		 cache_name?cache_name:"");
	exit(1);
    }

    code = krb5_os_localaddr(&my_addresses);
    if (code != 0) {
	com_err (argv[0], code, "when getting my address");
	exit(1);
    }	
#ifdef notyet
    code = krb5_get_in_tkt_with_password
	(flags, my_addresses, <<<enctype>>>,
	 <<<keytype>>>,
	 <<<char *>>>,
	 ccache,
	 my_creds,
	 <<<int>>>);
    if (code != 0) {
	com_err (argv[0], code, "getting initial credentials");
	exit(1);
    }
#endif
    exit(0);
}
