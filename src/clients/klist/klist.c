/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * List out the contents of your credential cache.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_klist_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <stdio.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <com_err.h>
#include <time.h>

extern int optind;
extern char *optarg;
int show_flags = 0;
char *progname;

void
show_credential PROTOTYPE((krb5_creds *));

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

    krb5_init_ets();

    if (strrchr(argv[0], '/'))
	progname = strrchr(argv[0], '/')+1;
    else
	progname = argv[0];

    while ((c = getopt(argc, argv, "fc:")) != EOF) {
	switch (c) {
	case 'f':
	     show_flags = 1;
	     break;
	case 'c':
	    if (cache == NULL) {
		cache_name = optarg;
		
		code = krb5_cc_resolve (cache_name, &cache);
		if (code != 0) {
		    com_err(progname, code, "while resolving %s", cache_name);
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
	fprintf(stderr, "Usage: %s [ -c cache ]\n", progname);
	exit(2);
    }
    if (cache == NULL) {
	if (code = krb5_cc_default(&cache)) {
	    com_err(progname, code, "while getting default ccache");
	    exit(1);
	}
    }

    flags = 0;				/* turns off OPENCLOSE mode */
    if (code = krb5_cc_set_flags(cache, flags)) {
	if (code == ENOENT) {
	    com_err(progname, code, "(ticket cache %s)",
		    krb5_cc_get_name(cache));
	} else
	    com_err(progname, code,
		    "while setting cache flags (ticket cache %s)",
		    krb5_cc_get_name(cache));
	exit(1);
    }
    if (code = krb5_cc_get_principal(cache, &princ)) {
	com_err(progname, code, "while retrieving principal name");
	exit(1);
    }
    if (code = krb5_unparse_name(princ, &name)) {
	com_err(progname, code, "while unparsing principal name");
	exit(1);
    }
    printf("Ticket cache: %s\nDefault principal: %s\n",
	   krb5_cc_get_name(cache), name);
    free(name);
    if (code = krb5_cc_start_seq_get(cache, &cur)) {
	com_err(progname, code, "while starting to retrieve tickets");
	exit(1);
    }
    while (!(code = krb5_cc_next_cred(cache, &cur, &creds)))
	show_credential(&creds);
    if (code == KRB5_CC_END) {
	if (code = krb5_cc_end_seq_get(cache, &cur)) {
	    com_err(progname, code, "while finishing ticket retrieval");
	    exit(1);
	}
	flags = KRB5_TC_OPENCLOSE;	/* turns on OPENCLOSE mode */
	if (code = krb5_cc_set_flags(cache, flags)) {
	    com_err(progname, code, "while closing ccache");
	    exit(1);
	}
	exit(0);
    } else {
	com_err(progname, code, "while retrieving a ticket");
	exit(1);
    }	
}

void
print_flags(cred)
register krb5_creds *cred;
{
    printf("F: %X (", cred->ticket_flags);
    if (cred->ticket_flags & TKT_FLG_FORWARDABLE)
	putchar('F');
    else
	putchar(' ');
    if (cred->ticket_flags & TKT_FLG_FORWARDED)
	putchar('f');
    else
	putchar(' ');
    if (cred->ticket_flags & TKT_FLG_PROXIABLE)
	putchar('P');
    else
	putchar(' ');
    if (cred->ticket_flags & TKT_FLG_PROXY)
	putchar('p');
    else
	putchar(' ');
    if (cred->ticket_flags & TKT_FLG_MAY_POSTDATE)
	putchar('D');
    else
	putchar(' ');
    if (cred->ticket_flags & TKT_FLG_POSTDATED)
	putchar('d');
    else
	putchar(' ');
    if (cred->ticket_flags & TKT_FLG_INVALID)
	putchar('i');
    else
	putchar(' ');
    if (cred->ticket_flags & TKT_FLG_RENEWABLE)
	putchar('R');
    else
	putchar(' ');
    if (cred->ticket_flags & TKT_FLG_INITIAL)
	putchar('I');
    else
	putchar(' ');
    putchar(')');
}

void
show_credential(cred)
register krb5_creds *cred;
{
    krb5_error_code retval;
    char *name, *sname;
    struct tm *stime;

    retval = krb5_unparse_name(cred->client, &name);
    if (retval) {
	com_err(progname, retval, "while unparsing client name");
	return;
    }
    retval = krb5_unparse_name(cred->server, &sname);
    if (retval) {
	com_err(progname, retval, "while unparsing server name");
	free(name);
	return;
    }
    printf("C: %s\tS: %s\n\t", name, sname);

    if (!cred->times.starttime)
	cred->times.starttime = cred->times.authtime;
    stime = localtime(&cred->times.starttime);
    printf("valid %02d/%02d/%02d:%02d:%02d:%02d to ",
	   stime->tm_year,
	   stime->tm_mon + 1,
	   stime->tm_mday,
	   stime->tm_hour,
	   stime->tm_min,
	   stime->tm_sec);
    stime = localtime(&cred->times.endtime);
    printf("%02d/%02d/%02d:%02d:%02d:%02d",
	   stime->tm_year,
	   stime->tm_mon + 1,
	   stime->tm_mday,
	   stime->tm_hour,
	   stime->tm_min,
	   stime->tm_sec);
    if (cred->times.renew_till) {
	stime = localtime(&cred->times.renew_till);
	printf("\n\trenew until %02d/%02d/%02d:%02d:%02d:%02d",
	       stime->tm_year,
	       stime->tm_mon + 1,
	       stime->tm_mday,
	       stime->tm_hour,
	       stime->tm_min,
	       stime->tm_sec);
    }
    if (show_flags) {
	fputs("\n\t",stdout);
	print_flags(cred);
    }
    putchar('\n');
    free(name);
    free(sname);
}
