/*
 * lib/kadm/t_ktentry.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 */

/*
 * t_ktentry.c	- Test function of krb5_adm_{proto_to_ktent,ktent_to_proto}.
 */

#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"

#if	HAVE_SRAND48
#define	SRAND	srand48
#define	RAND	lrand48
#define	RAND_TYPE	long
#endif	/* HAVE_SRAND48 */

#if	!defined(RAND_TYPE) && defined(HAVE_SRAND)
#define	SRAND	srand
#define	RAND	rand
#define	RAND_TYPE	int
#endif	/* !defined(RAND_TYPE) && defined(HAVE_SRAND) */

#if	!defined(RAND_TYPE) && defined(HAVE_SRANDOM)
#define	SRAND	srandom
#define	RAND	random
#define	RAND_TYPE	long
#endif	/* !defined(RAND_TYPE) && defined(HAVE_SRANDOM) */

#if	!defined(RAND_TYPE)
There is no random number generator.
#endif	/* !defined(RAND_TYPE) */

/*
 * Generate a principal name.
 */
static char *
gen_princname(isrand)
    krb5_boolean	isrand;
{
    static char	*defprinc = "testprinc/instance@realm";
    char *pptr;

    if (isrand) {
	int i, j;
	int ncomps;
	size_t compsize[9];
	char * complist[9];
	size_t	totsize;

	for (i=0; i<9; i++) {
	    compsize[i] = 0;
	    complist[i] = (char *) NULL;
	}
	ncomps = 2 + (RAND() % 7);
	totsize = 0;
	for (i=0; i<ncomps; i++) {
	    compsize[i] = 1 + (RAND() % 32);
	    complist[i] = (char *) malloc(compsize[i]+1);
	    if (complist[i]) {
		for (j=0; j<compsize[i]; j++) {
		    (complist[i])[j] = RAND() % 128;
		    while (!isalnum((int) (complist[i])[j]))
			(complist[i])[j] = RAND() % 128;
		}
		(complist[i])[compsize[i]] = '\0';
		totsize += (compsize[i] + 1);
	    }
	    else
		break;
	}
	pptr = (char *) malloc(totsize+1);
	if (pptr) {
	    pptr[0] = '\0';
	    for (i=1; i<ncomps; i++) {
		if (complist[i]) {
		    strcat(pptr, complist[i]);
		    strcat(pptr, "/");
		    free(complist[i]);
		}
		else
		    break;
	    }
	    pptr[strlen(pptr)-1] = '\0';
	    strcat(pptr, "@");
	    strcat(pptr, complist[0]);
	    free(complist[0]);
	}
    }
    else {
	pptr = (char *) malloc(strlen(defprinc)+1);
	if (pptr)
	    strcpy(pptr, defprinc);
    }
    return(pptr);
}

static void
gen_key(ktentp, isrand)
    krb5_keytab_entry	*ktentp;
    krb5_boolean	isrand;
{
    static unsigned char defkey[8] = { 0x01, 0xfe, 0xab, 0xc3,
					   0x23, 0x16, 0x84, 0x23 };

    if (isrand) {
	size_t keylen;
	int i;

	keylen = 4 + (RAND() % 64);
	ktentp->key.contents = (krb5_octet *) malloc(keylen);
	if (ktentp->key.contents) {
	    ktentp->key.length = keylen;
	    for (i=0; i<keylen; i++)
		ktentp->key.contents[i] = RAND() & 255;
	}
    }
    else {
	ktentp->key.contents = (krb5_octet *) malloc(sizeof(defkey));
	if (ktentp->key.contents) {
	    ktentp->key.length = 8;
	    memcpy(ktentp->key.contents, defkey, sizeof(defkey));
	}
    }
}

/*
 * Generate a keytab entry.
 */
static void
gen_ktent(kcontext, ktentp, isrand)
    krb5_context	kcontext;
    krb5_keytab_entry	*ktentp;
    krb5_boolean	isrand;
{
    char	*princname;

    princname = gen_princname(isrand);
    if (princname && !krb5_parse_name(kcontext,
				      princname,
				      &ktentp->principal)
	) {
	ktentp->vno = (isrand) ? RAND() : 1;
	gen_key(ktentp, isrand);
	free(princname);
    }
}

/*
 * Compare two entries.
 */
static krb5_boolean
compare_entries(kcontext, ientp, oentp)
    krb5_context	kcontext;
    krb5_keytab_entry	*ientp;
    krb5_keytab_entry	*oentp;
{
    if (ientp->vno != oentp->vno)
	return(0);

    if ((ientp->key.length != oentp->key.length) ||
	memcmp(ientp->key.contents, oentp->key.contents, ientp->key.length))
	return(0);

    if (!krb5_principal_compare(kcontext, ientp->principal, oentp->principal))
	return(0);
    return(1);
}

/*
 * Print out an entry.
 */
static void
print_ktent(kcontext, ientp)
    krb5_context	kcontext;
    krb5_keytab_entry	*ientp;
{
    char *princname;
    int i;

    if (!krb5_unparse_name(kcontext, ientp->principal, &princname)) {
	printf("Principal: %s (version %d[%x])\n", princname, ientp->vno);
	printf("Key:");
	for (i=0; i<ientp->key.length; i++)
	    printf(" %02x", ientp->key.contents[i]);
	printf("\n");
	krb5_xfree(princname);
    }
}

/*
 * Do a test case.
 *
 * Strategy: Generate the desired keytab entry type, then convert it using
 *	krb5_adm_ktent_to_proto, then convert it back to a keytab entry
 *	using krb5_adm_proto_to_ktent.  Then verify the match.
 */
static krb5_int32
do_test(pname, verbose, isrand, title, passno)
    char		*pname;
    krb5_boolean	verbose;
    krb5_boolean	isrand;
    char		*title;
    krb5_int32		passno;
{
    krb5_context	kcontext;
    krb5_keytab_entry	*in_ktent;
    krb5_keytab_entry	*out_ktent;
    krb5_error_code	kret;
    krb5_int32		ncomps;
    krb5_data		*complist;

    if (verbose) {
	printf("* Begin %s", title);
	if (isrand)
	    printf(" pass %d", passno);
	printf("\n");
    }

    kret = 0;
    krb5_init_context(&kcontext);
    in_ktent = (krb5_keytab_entry *) malloc(sizeof(krb5_keytab_entry));
    out_ktent = (krb5_keytab_entry *) malloc(sizeof(krb5_keytab_entry));
    if (in_ktent && out_ktent) {
	/* Initialize our data */
	memset((char *) in_ktent, 0, sizeof(krb5_keytab_entry));
	memset((char *) out_ktent, 0, sizeof(krb5_keytab_entry));
	ncomps = 0;
	complist = (krb5_data *) NULL;

	/* Generate the keytab entry. */
	gen_ktent(kcontext, in_ktent, isrand);

	/* Convert it to the o-t-w protocol */
	if (!(kret = krb5_adm_ktent_to_proto(kcontext,
					     in_ktent,
					     &ncomps,
					     &complist))) {
		/* Otherwise, convert it back to a keytab entry */
		if (!(kret = krb5_adm_proto_to_ktent(kcontext,
						     ncomps,
						     complist,
						     out_ktent))) {
		    /* Compare the entries */
		    if (compare_entries(kcontext,
					in_ktent,
					out_ktent)) {
			/* Success */
			if (verbose) {
			    printf("Successful translation");
			    printf(" during %s", title);
			    if (isrand)
				printf(" pass %d", passno);
			    printf(" of:\n");
			    print_ktent(kcontext, in_ktent);
			}
		    }
		    else {
			/* Failed */
			fprintf(stderr, "%s: comparison mismatch", pname);
			fprintf(stderr, " during %s", title);
			if (isrand)
			    fprintf(stderr, " pass %d", passno);
			fprintf(stderr, "\n");
			if (verbose) {
			    printf("Input entry is as follows:\n");
			    print_ktent(kcontext, in_ktent);
			    printf("Output entry is as follows:\n");
			    print_ktent(kcontext, out_ktent);
			}
			kret = KRB5KRB_ERR_GENERIC;
		    }
		}
		else {
		    /* Conversion to keytab entry failed */
		    fprintf(stderr, "%s: protocol decode failed with %d",
			pname, kret);
		    fprintf(stderr, " during %s", title);
		    if (isrand)
			fprintf(stderr, " pass %d", passno);
		    fprintf(stderr, "\n");
		}
	    krb5_free_adm_data(kcontext, ncomps, complist);
	}
	else {
	    /* Convert to protocol failed */
		fprintf(stderr, "%s: protocol encode failed with %d",
			pname, kret);
		fprintf(stderr, " during %s", title);
		if (isrand)
		    fprintf(stderr, " pass %d", passno);
		fprintf(stderr, "\n");
	}
	/* Cleanup */
	if (in_ktent->principal)
	    krb5_free_principal(kcontext, in_ktent->principal);
	if (in_ktent->key.contents)
	    free(in_ktent->key.contents);
	free(in_ktent);
	if (out_ktent->principal)
	    krb5_free_principal(kcontext, out_ktent->principal);
	if (out_ktent->key.contents)
	    free(out_ktent->key.contents);
	free(out_ktent);
    }
    else {
	fprintf(stderr, "%s: no memory\n", pname);
	kret = ENOMEM;
    }

    krb5_free_context(kcontext);
    if (verbose) {
	printf("* End %s ", title);
	if (isrand)
	    printf(" pass %d ", passno);
	printf("%s", (kret) ? "FAILURE" : "SUCCESS");
	if (kret)
	    printf("%d - %s", kret, error_message(kret));
	printf("\n");
    }
    return((kret) ? 1 : 0);
}

/*
 * usage is: t_ktentry [-r <nnn>] [-v]
 */
int
main(argc, argv)
    int		argc;
    char	*argv[];
{
    krb5_boolean	verbose;
    krb5_int32		randompasses;
    krb5_int32		error;
    int		option;
    extern char		*optarg;
    char		*programname;
    int			i;
    time_t		now;

    randompasses = 0;
    verbose = 0;
    error = 0;
    programname = argv[0];

    now = time((time_t *) NULL);
    SRAND((RAND_TYPE) now);
    while ((option = getopt(argc, argv, "r:v")) != EOF) {
	switch (option) {
	case 'r':
	    if (sscanf(optarg, "%d", &randompasses) != 1) {
		fprintf(stderr, "%s: %s is not a number\n", argv[0], optarg);
		error++;
	    }
	    break;
	case 'v':
	    verbose = 1;
	    break;
	default:
	    fprintf(stderr, "%s: usage is %s [-r number] [-v]\n",
		    argv[0], argv[0]);
	    error++;
	    break;
	}
    }
    if (error)
	return(error);

    error += do_test(programname, verbose, 0, "Standard test", 0);
    for (i=0; i<randompasses; i++)
	error += do_test(programname, verbose, 1, 0, "Random test", i+1);
    if (verbose) {
	if (error)
	    printf("%s: %d errors in %d tests (%5.2f%%)\n", argv[0], error,
		   randompasses+2,
		   (float) (error*100) / (float) (randompasses+2));
    }
    return(error);
}

