/*
 * clients/klist/klist.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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
 * List out the contents of your credential cache.
 */

#include <stdio.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <com_err.h>
#include <time.h>

extern int optind;
extern char *optarg;
int show_flags = 0;
char *progname;
char *defname;
time_t now;

void
show_credential 
	PROTOTYPE((krb5_context,
		   krb5_creds *));

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
    krb5_flags flags;
    krb5_context kcontext;

    krb5_init_ets(kcontext);

    time(&now);
    
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
		
		code = krb5_cc_resolve (kcontext, cache_name, &cache);
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
	if (code = krb5_cc_default(kcontext, &cache)) {
	    com_err(progname, code, "while getting default ccache");
	    exit(1);
	}
    }

    flags = 0;				/* turns off OPENCLOSE mode */
    if (code = krb5_cc_set_flags(kcontext, cache, flags)) {
	if (code == ENOENT) {
	    com_err(progname, code, "(ticket cache %s)",
		    krb5_cc_get_name(kcontext, cache));
	} else
	    com_err(progname, code,
		    "while setting cache flags (ticket cache %s)",
		    krb5_cc_get_name(kcontext, cache));
	exit(1);
    }
    if (code = krb5_cc_get_principal(kcontext, cache, &princ)) {
	com_err(progname, code, "while retrieving principal name");
	exit(1);
    }
    if (code = krb5_unparse_name(kcontext, princ, &defname)) {
	com_err(progname, code, "while unparsing principal name");
	exit(1);
    }
    printf("Ticket cache: %s\nDefault principal: %s\n\n",
           krb5_cc_get_name(kcontext, cache), defname);
    if (code = krb5_cc_start_seq_get(kcontext, cache, &cur)) {
	com_err(progname, code, "while starting to retrieve tickets");
	exit(1);
    }
    fputs("  Valid starting       Expires          Service principal\n",
	  stdout);
    while (!(code = krb5_cc_next_cred(kcontext, cache, &cur, &creds))) {
	show_credential(kcontext, &creds);
	krb5_free_cred_contents(kcontext, &creds);
    }
    if (code == KRB5_CC_END) {
	if (code = krb5_cc_end_seq_get(kcontext, cache, &cur)) {
	    com_err(progname, code, "while finishing ticket retrieval");
	    exit(1);
	}
	flags = KRB5_TC_OPENCLOSE;	/* turns on OPENCLOSE mode */
	if (code = krb5_cc_set_flags(kcontext, cache, flags)) {
	    com_err(progname, code, "while closing ccache");
	    exit(1);
	}
	exit(0);
    } else {
	com_err(progname, code, "while retrieving a ticket");
	exit(1);
    }	
}

char *
flags_string(cred)
    register krb5_creds *cred;
{
    static char buf[32];
    int i = 0;
	
    if (cred->ticket_flags & TKT_FLG_FORWARDABLE)
        buf[i++] = 'F';
    if (cred->ticket_flags & TKT_FLG_FORWARDED)
        buf[i++] = 'f';
    if (cred->ticket_flags & TKT_FLG_PROXIABLE)
        buf[i++] = 'P';
    if (cred->ticket_flags & TKT_FLG_PROXY)
        buf[i++] = 'p';
    if (cred->ticket_flags & TKT_FLG_MAY_POSTDATE)
        buf[i++] = 'D';
    if (cred->ticket_flags & TKT_FLG_POSTDATED)
        buf[i++] = 'd';
    if (cred->ticket_flags & TKT_FLG_INVALID)
        buf[i++] = 'i';
    if (cred->ticket_flags & TKT_FLG_RENEWABLE)
        buf[i++] = 'R';
    if (cred->ticket_flags & TKT_FLG_INITIAL)
        buf[i++] = 'I';
    if (cred->ticket_flags & TKT_FLG_HW_AUTH)
        buf[i++] = 'H';
    if (cred->ticket_flags & TKT_FLG_PRE_AUTH)
        buf[i++] = 'A';
    buf[i] = '\0';
    return(buf);
}

static  char *Month_names[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
				"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

void 
printtime(tv)
    time_t tv;
{
    struct tm *stime;

    stime = localtime((time_t *)&tv);
    printf("%2d-%s-%2d %02d:%02d:%02d",
           stime->tm_mday,
           Month_names[stime->tm_mon],
           stime->tm_year,
           stime->tm_hour,
           stime->tm_min,
           stime->tm_sec);
}

void
show_credential(kcontext, cred)
    krb5_context kcontext;
    register krb5_creds *cred;
{
    krb5_error_code retval;
    char *name, *sname, *flags;
    int	first = 1;

    retval = krb5_unparse_name(kcontext, cred->client, &name);
    if (retval) {
	com_err(progname, retval, "while unparsing client name");
	return;
    }
    retval = krb5_unparse_name(kcontext, cred->server, &sname);
    if (retval) {
	com_err(progname, retval, "while unparsing server name");
	free(name);
	return;
    }
    if (!cred->times.starttime)
	cred->times.starttime = cred->times.authtime;

    printtime(cred->times.starttime);
    putchar(' '); putchar(' ');
    printtime(cred->times.endtime);
    putchar(' '); putchar(' ');

    printf("%s\n", sname);

    if (strcmp(name, defname)) {
	    printf("\tfor client %s", name);
	    first = 0;
    }
    
    if (cred->times.renew_till) {
	if (first)
		fputs("\t",stdout);
	else
		fputs(", ",stdout);
	fputs("renew until ", stdout);
        printtime(cred->times.renew_till);
    }
    if (show_flags) {
	flags = flags_string(cred);
	if (flags && *flags) {
	    if (first)
		fputs("\t",stdout);
	    else
		fputs(", ",stdout);
	    printf("Flags: %s", flags);
	    first = 0;
        }
    }
    putchar('\n');
    free(name);
    free(sname);
}

