/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * List out the contents of your credential cache.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_klist_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <stdio.h>

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/isode_err.h>
#include <krb5/ext-proto.h>
#include <com_err.h>

extern int optind;
extern char *optarg;

void
main(argc, argv)
    int argc;
    char **argv;
{
    int c;
    int errflg = 0;
    int code;
    krb5_ccache cache = NULL;
    krb5_cc_cursor cur;
    krb5_creds creds;
    char *cache_name;
    krb5_principal princ;
    char *name, *sname;
    krb5_flags flags;

    initialize_krb5_error_table();
    initialize_isod_error_table();


    if (rindex(argv[0], '/'))
	argv[0] = rindex(argv[0], '/')+1;

    while ((c = getopt(argc, argv, "c:")) != EOF) {
	switch (c) {
	case 'c':
	    if (cache == NULL) {
		cache_name = optarg;
		
		code = krb5_cc_resolve (cache_name, &cache);
		if (code != 0) {
		    com_err(argv[0], code, "while resolving %s", cache_name);
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
	fprintf(stderr, "Usage: %s [ -c cache ]\n", argv[0]);
	exit(2);
    }
    if (cache == NULL)
	cache = krb5_cc_default();

    flags = 0;				/* turns off OPENCLOSE mode */
    if (code = (*cache->ops->set_flags)(cache, flags)) {
	com_err(argv[0], code, "while setting cache flags");
	exit(1);
    }
    if (code = (*cache->ops->get_princ)(cache, &princ)) {
	com_err(argv[0], code, "while retrieving principal name");
	exit(1);
    }
    if (code = krb5_unparse_name(princ, &name)) {
	com_err(argv[0], code, "while unparsing principal name");
	exit(1);
    }
    printf("Ticket cache: %s\nDefault principal: %s\n",
	   (*cache->ops->get_name)(cache), name);
    free(name);
    if (code = (*cache->ops->get_first)(cache, &cur)) {
	com_err(argv[0], code, "while starting to retrieve tickets");
	exit(1);
    }
    while (!(code = (*cache->ops->get_next)(cache, &cur, &creds))) {
	code = krb5_unparse_name(creds.client, &name);
	if (code) {
	    com_err(argv[0], code, "while unparsing client name");
	    continue;
	}
	code = krb5_unparse_name(creds.server, &sname);
	if (code) {
	    com_err(argv[0], code, "while unparsing server name");
	    free(name);
	    continue;
	}
	printf("C: %s\tS:%s\n", name, sname);
    }
    if (code == KRB5_CC_END) {
	if (code = (*cache->ops->end_get)(cache, &cur)) {
	    com_err(argv[0], code, "while finishing ticket retrieval");
	    exit(1);
	}
	exit(0);
    } else {
	com_err(argv[0], code, "while retrieving a ticket");
	exit(1);
    }	
}
