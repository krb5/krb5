/*
 * kdc/rtest.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"
#include <stdio.h>
#include "kdc_util.h"

void
main(argc,argv)
    int	argc;
    char *argv[];
    {
	krb5_data otrans;
	krb5_data ntrans;

	krb5_data *tgnames[10];
	krb5_principal tgs = tgnames;
	krb5_data tgsrlm;

	krb5_data *cnames[10];
	krb5_principal cl = cnames;
	krb5_data crlm;

	krb5_data *snames[10];
	krb5_principal sv = snames;
	krb5_data srlm;

	if (argc < 4) {
	    fprintf(stderr, "not enough args\n");
	    exit(1);
	}
	ntrans.length = 0;
	otrans.length = strlen(argv[1]) + 1;
	otrans.data = (char *) malloc(otrans.length);
	strcpy(otrans.data,argv[1]);

	tgsrlm.length = strlen(argv[2]) + 1;
	tgsrlm.data = (char *) malloc(tgsrlm.length);
	strcpy(tgsrlm.data,argv[2]);
	tgs[0] = &tgsrlm;

	crlm.length = strlen(argv[3]) + 1;
	crlm.data = (char *) malloc(crlm.length);
	strcpy(crlm.data,argv[3]);
	cl[0] = &crlm;

	srlm.length = strlen(argv[4]) + 1;
	srlm.data = (char *) malloc(srlm.length);
	strcpy(srlm.data,argv[4]);
	sv[0] = &srlm;
	
	add_to_transited(&otrans,&ntrans,tgs,cl,sv);

	printf("%s\n",ntrans.data);

    }

krb5_encrypt_block master_encblock;
