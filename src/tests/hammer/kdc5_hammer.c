/*
 * tests/hammer/kdc5_hammer.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Initialize a credentials cache.
 */

#include <stdio.h>

#include <krb5/copyright.h>
#include <krb5/osconf.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>

#include <com_err.h>

#define KRB5_DEFAULT_OPTIONS 0
#define KRB5_DEFAULT_LIFE 60*60*8 /* 8 hours */
#define KRB5_RENEWABLE_LIFE 60*60*2 /* 2 hours */

extern int optind;
extern char *optarg;
char *prog;

static int brief;
static char *cur_realm = 0;

krb5_error_code
krb5_parse_lifetime (time, len)
    char *time;
    long *len;
{
    *len = atoi (time) * 60 * 60; /* XXX stub version */
    return 0;
}
    
krb5_data tgtname = {
    0, 
    KRB5_TGS_NAME_SIZE,
    KRB5_TGS_NAME
};

int verify_cs_pair PROTOTYPE((char *,
			      krb5_principal,
			      char *,
			      int, int, int,
			      krb5_ccache));
int get_tgt PROTOTYPE((char *,
		       krb5_principal *,
		       krb5_ccache));

static void
usage(who, status)
char *who;
int status;
{
    fprintf(stderr,
	    "usage: %s -p prefix -n num_to_check [-d dbpathname] [-r realmname]\n",
	    who);
    fprintf(stderr, "\t [-D depth] [-k keytype] [-e etype] [-M mkeyname]\n");
    fprintf(stderr, "\t [-P preauth type] [-R repeat_count]\n");

    exit(status);
}

static krb5_enctype etype = 0xffff;
static krb5_preauthtype patype = KRB5_PADATA_NONE;
static krb5_keytype keytype;

void
main(argc, argv)
    int argc;
    char **argv;
{
    krb5_ccache ccache = NULL;
    char *cache_name = NULL;		/* -f option */
    int option;
    int errflg = 0;
    krb5_error_code code;
    int num_to_check, n, i, j, repeat_count, counter;
    int n_tried, errors, keytypedone;
    char prefix[BUFSIZ], client[4096], server[4096];
    int depth;
    char ctmp[4096], ctmp2[BUFSIZ], stmp[4096], stmp2[BUFSIZ];
    krb5_principal client_princ;
    krb5_error_code retval;

    krb5_init_ets();

    if (strrchr(argv[0], '/'))
	prog = strrchr(argv[0], '/')+1;
    else
	prog = argv[0];

    num_to_check = 0;
    depth = 1;
    repeat_count = 1;
    brief = 0;
    n_tried = 0;
    errors = 0;
    keytypedone = 0;

    while ((option = getopt(argc, argv, "D:p:n:c:R:k:P:e:bv")) != EOF) {
	switch (option) {
	case 'b':
	    brief = 1;
	    break;
	case 'v':
	    brief = 0;
	    break;
	case 'R':
	    repeat_count = atoi(optarg); /* how many times? */
	    break;
	case 'r':
	    cur_realm = optarg;
	    break;
	case 'D':
	    depth = atoi(optarg);       /* how deep to go */
	    break;
	case 'p':                       /* prefix name to check */
	    strcpy(prefix, optarg);
	    break;
       case 'n':                        /* how many to check */
	    num_to_check = atoi(optarg);
	    break;
	case 'k':
	    keytype = atoi(optarg);
	    keytypedone++;
	    break;
	case 'e':
	    etype = atoi(optarg);
	    break;
	case 'P':
	    patype = atoi(optarg);
	    break;
	case 'c':
	    if (ccache == NULL) {
		cache_name = optarg;
		
		code = krb5_cc_resolve (cache_name, &ccache);
		if (code != 0) {
		    com_err (prog, code, "resolving %s", cache_name);
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

    if (!(num_to_check && prefix[0])) usage(prog, 1);

    if (!keytypedone)
	keytype = DEFAULT_KDC_KEYTYPE;

    if (!cur_realm) {
	if (retval = krb5_get_default_realm(&cur_realm)) {
	    com_err(prog, retval, "while retrieving default realm name");
	    exit(1);
	}	    
    }

    if (!valid_keytype(keytype)) {
      com_err(prog, KRB5_PROG_KEYTYPE_NOSUPP,
	      "while setting up keytype %d", keytype);
      exit(1);
    }

    if (etype == 0xffff)
	etype = krb5_keytype_array[keytype]->system->proto_enctype;

    if (!valid_etype(etype)) {
	com_err(prog, KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", etype);
	exit(1);
    }

    if (ccache == NULL) {
	if (code = krb5_cc_default(&ccache)) {
	    com_err(prog, code, "while getting default ccache");
	    exit(1);
	}
    }

    memset(ctmp, 0, sizeof(ctmp));
    memset(stmp, 0, sizeof(stmp));

    for (counter = 0; counter < repeat_count; counter++) {
      fprintf(stderr, "\nRound %d\n", counter);

      for (n = 1; n <= num_to_check; n++) {
	/* build the new principal name */
	/* we can't pick random names because we need to generate all the names 
	   again given a prefix and count to test the db lib and kdb */
	ctmp[0] = '\0';
	for (i = 1; i <= depth; i++) {
	  ctmp2[0] = '\0';
	  (void) sprintf(ctmp2, "%s%s%d-DEPTH-%d", (i != 1) ? "/" : "",
			 prefix, n, i);
	  strcat(ctmp, ctmp2);
	  sprintf(client, "%s@%s", ctmp, cur_realm);

	  if (get_tgt (client, &client_princ, ccache)) {
	    errors++;
	    n_tried++;
	    continue;
	  }
	  n_tried++;

	  stmp[0] = '\0';
	  for (j = 1; j <= depth; j++) {
	    stmp2[0] = '\0';
	    (void) sprintf(stmp2, "%s%s%d-DEPTH-%d", (j != 1) ? "/" : "",
			   prefix, n, j);
	    strcat(stmp, stmp2);
	    sprintf(server, "%s@%s", stmp, cur_realm);
	    if (verify_cs_pair(client, client_princ, server, n, i, j, ccache))
	      errors++;
	    n_tried++;
	  }
	  krb5_free_principal(client_princ);
	}
      }
    }
    fprintf (stderr, "\nTried %d.  Got %d errors.\n", n_tried, errors);
  }

       
#include <krb5/widen.h>
krb5_error_code get_server_key(DECLARG(krb5_pointer,keyprocarg),
			       DECLARG(krb5_principal,princ),
			       DECLARG(krb5_kvno,vno),
			       DECLARG(krb5_keyblock **,key))
OLDDECLARG(krb5_pointer,keyprocarg)
OLDDECLARG(krb5_principal,princ)
OLDDECLARG(krb5_kvno,vno)
OLDDECLARG(krb5_keyblock **,key)
#include <krb5/narrow.h>
{
  krb5_data pwd, salt;
  char *princ_str, *at;
  krb5_error_code code;
  /* Jon Rochlis asks: Does this belong here or in libos or something? */
  /* John Kohl replies: not really; it's not a generally useful function */

  code = krb5_unparse_name(princ, &princ_str);
  if (code) {
    com_err (prog, code, "while unparsing server name");
    return(code);
  }

  /* The kdb5_create does not include realm names in the password ... 
     this is ugly */
  at = strchr(princ_str, '@');
  if (at) *at = '\0';

  pwd.data = princ_str;
  pwd.length = strlen(princ_str);
  
  if (code = krb5_principal2salt(princ, &salt)) {
    com_err(prog, code, "while converting principal to salt for '%s'", princ_str);
    goto errout;
  }

  *key = (krb5_keyblock *)malloc(sizeof(**key));
  if (!*key) {
    code = ENOMEM;
    com_err(prog, code, "while allocating key for server %s", princ_str);
    goto errout;
  }    
  if (code = (*krb5_keytype_array[keytype]->system->
		string_to_key)(keytype,
			       *key,
			       &pwd,
			       &salt))
    goto errout;

out:
  if (princ_str) free(princ_str);
  if (salt.data) free(salt.data);
  return(code);

  errout:
  if (*key) krb5_xfree(*key);
  goto out;

}

int verify_cs_pair(p_client_str, p_client, p_server_str, p_num, 
		   c_depth, s_depth, ccache)
     char *p_client_str;
     krb5_principal p_client;
     char *p_server_str;
     int p_num, c_depth, s_depth;
     krb5_ccache ccache;
{
    krb5_error_code code;
    krb5_principal server;
    krb5_data request_data;
    char *returned_client;
    krb5_tkt_authent *authdat;

    if (brief)
      fprintf(stderr, "\tprinc (%d) client (%d) for server (%d)\n", 
	      p_num, c_depth, s_depth);
    else
      fprintf(stderr, "\tclient %s for server %s\n", p_client_str, 
	      p_server_str);

    if (code = krb5_parse_name (p_server_str, &server)) {
      com_err (prog, code, "when parsing name %s", p_server_str);
      return(-1);
    }

    /* test the checksum stuff? */
    if (code = krb5_mk_req(server, 0, 0, ccache, &request_data)) {
	com_err(prog, code, "while preparing AP_REQ for %s", p_server_str);
	return(-1);
    }

    if (code = krb5_rd_req(&request_data, server, 0, 0, get_server_key, 0, 0, 
			   &authdat)) {
	com_err(prog, code, "while decoding AP_REQ for %s", p_server_str);
	return(-1);
    }

    if (!krb5_principal_compare(authdat->authenticator->client, p_client)) {
      code = krb5_unparse_name(authdat->authenticator->client, &returned_client);
      if (code)
	com_err (prog, code, 
		 "Client not as expected, but cannot unparse client name");
      else
	com_err (prog, 0, "Client not as expected (%s).", returned_client);
      krb5_free_tkt_authent(authdat);
      free(returned_client);
      return(-1);
    }

    krb5_free_tkt_authent(authdat);
    krb5_free_principal(server);
    if (request_data.data) krb5_xfree(request_data.data);

    return(0);
}

int get_tgt (p_client_str, p_client, ccache)
     char *p_client_str;
     krb5_principal *p_client;
     krb5_ccache ccache;
{
    char *cache_name = NULL;		/* -f option */
    long lifetime = KRB5_DEFAULT_LIFE;	/* -l option */
    int options = KRB5_DEFAULT_OPTIONS;
    krb5_address **my_addresses;
    krb5_error_code code;
    krb5_creds my_creds;
    krb5_timestamp start;
    krb5_principal tgt_server;

    if (!brief)
      fprintf(stderr, "\tgetting TGT for %s\n", p_client_str);

    if (code = krb5_timeofday(&start)) {
	com_err(prog, code, "while getting time of day");
	return(-1);
    }

    memset((char *)&my_creds, 0, sizeof(my_creds));
    
    if (code = krb5_parse_name (p_client_str, p_client)) {
	com_err (prog, code, "when parsing name %s", p_client_str);
	return(-1);
    }


    if (code = krb5_build_principal_ext(&tgt_server,
					krb5_princ_realm(*p_client)->length,
					krb5_princ_realm(*p_client)->data,
					tgtname.length,
					tgtname.data,
					krb5_princ_realm(*p_client)->length,
					krb5_princ_realm(*p_client)->data,
					0)) {
	com_err(prog, code, "when setting up tgt principal");
	return(-1);
    }

    code = krb5_os_localaddr(&my_addresses);
    if (code != 0) {
	com_err (prog, code, "when getting my address");
	exit(1);
    }

    my_creds.client = *p_client;
    my_creds.server = tgt_server;

    krb5_cc_destroy(ccache);  /* ugh, I'd much rather just delete the credential */

    code = krb5_cc_initialize (ccache, *p_client);
    if (code != 0) {
	com_err (prog, code, "when initializing cache %s",
		 cache_name?cache_name:"");
	return(-1);
    }

    my_creds.times.starttime = 0;	/* start timer when request
					   gets to KDC */
    my_creds.times.endtime = start + lifetime;
    my_creds.times.renew_till = 0;

    code = krb5_get_in_tkt_with_password(options, my_addresses,
					 patype,
					 etype,
					 keytype,
					 p_client_str,
					 ccache,
					 &my_creds, 0);
    my_creds.server = my_creds.client = 0;
    krb5_free_principal(tgt_server);
    krb5_free_addresses(my_addresses);
    krb5_free_cred_contents(&my_creds);
    if (code != 0) {
	com_err (prog, code, "while getting initial credentials");
	return(-1);
      }

    return(0);
}
