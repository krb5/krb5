/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Destroy the contents of your credential cache.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_klist_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <stdio.h>

#include <krb5/copyright.h>
#include <krb5/krb5.h>

extern int optind;
extern char *optarg;

main(argc, argv)
    int argc;
    char **argv;
{
    int c;
    krb5_ccache cache = NULL;
    char *cache_name = NULL;
    int code;
    int errflg=0;
    
    initialize_krb5_error_table();
    
    while ((c = getopt(argc, argv, "c:")) != EOF) {
	switch (c) {
	case 'c':
	    if (cache == NULL) {
		cache_name = optarg;
		
		code = krb5_cc_resolve (cache_name, &cache);
		if (code != 0) {
		    com_err (argv[0], code, "while resolving %s", cache_name);
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

    if (optind != argc)
	errflg++;
    
    if (errflg) {
	fprintf(stderr, "Usage: %s [ -c cache-name ]\n", argv[0]);
	exit(2);
    }

    if (cache == NULL)
	cache = krb5_cc_default ();

    code = krb5_cc_destroy (cache);
    if (code != 0) {
	com_err (argv[0], code, "while destroying cache");
	fprintf(stderr, "Ticket cache \007NOT\007 destroyed!\n");
	exit (1);
    }
    exit (0);
}
