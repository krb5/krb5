/*
 * t_std_conf.c --- This program tests standard Krb5 routines which pull 
 * 	values from the krb5 config file(s).
 */

#include "krb5.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void test_get_default_realm(ctx)
	krb5_context ctx;
{
	char	*realm;
	krb5_error_code	retval;
	
	retval = krb5_get_default_realm(ctx, &realm);
	if (retval) {
		com_err("krb5_get_default_realm", retval, 0);
		return;
	}
	printf("krb5_get_default_realm() returned '%s'\n", realm);
	free(realm);
}

void test_set_default_realm(ctx, realm)
    krb5_context ctx;
    char	*realm;
{
	krb5_error_code	retval;
	
	retval = krb5_set_default_realm(ctx, realm);
	if (retval) {
		com_err("krb5_set_default_realm", retval, 0);
		return;
	}
	printf("krb5_set_default_realm(%s)\n", realm);
}

void test_get_krbhst(ctx, realm)
	krb5_context ctx;
	char	*realm;
{
	char **hostlist, **cpp;
	krb5_data rlm;
	krb5_error_code	retval;

	rlm.data = realm;
	rlm.length = strlen(realm);
	retval = krb5_get_krbhst(ctx, &rlm, &hostlist);
	if (retval) {
		com_err("krb5_get_krbhst", retval, 0);
		return;
	}
	printf("krb_get_krbhst(%s) returned:", realm);
	if (hostlist == 0) {
		printf(" (null)\n");
		return;
	}
	if (hostlist[0] == 0) {
		printf(" (none)\n");
		free(hostlist);
		return;
	}
	for (cpp = hostlist; *cpp; cpp++) {
		printf(" '%s'", *cpp);
		free(*cpp);
	}
	free(hostlist);
	printf("\n");
}

void test_locate_kdc(ctx, realm)
	krb5_context ctx;
	char	*realm;
{
    	struct sockaddr *addrs;
	struct sockaddr_in *sin;
	int	i, naddrs;
	krb5_data rlm;
	krb5_error_code	retval;

	rlm.data = realm;
	rlm.length = strlen(realm);
	retval = krb5_locate_kdc(ctx, &rlm, &addrs, &naddrs);
	if (retval) {
		com_err("krb5_get_krbhst", retval, 0);
		return;
	}
	printf("krb_get_krbhst(%s) returned:", realm);
	for (i=0; i < naddrs; i++) {
	    sin = (struct sockaddr_in *) &addrs[i];
	    printf(" %s/%d", inet_ntoa(sin->sin_addr), 
		   ntohs(sin->sin_port));
	}
	free(addrs);
	printf("\n");
}

void test_get_host_realm(ctx, host)
	krb5_context ctx;
	char	*host;
{
	char **realms, **cpp;
	krb5_error_code retval;

	retval = krb5_get_host_realm(ctx, host, &realms);
	if (retval) {
		com_err("krb5_get_host_realm", retval, 0);
		return;
	}
	printf("krb_get_host_realm(%s) returned:", host);
	if (realms == 0) {
		printf(" (null)\n");
		return;
	}
	if (realms[0] == 0) {
		printf(" (none)\n");
		free(realms);
		return;
	}
	for (cpp = realms; *cpp; cpp++) {
		printf(" '%s'", *cpp);
		free(*cpp);
	}
	free(realms);
	printf("\n");
}

void test_get_realm_domain(ctx, realm)
	krb5_context ctx;
	char	*realm;
{
	krb5_error_code	retval;
	char	*domain;
	
	retval = krb5_get_realm_domain(ctx, realm, &domain);
	if (retval) {
		com_err("krb5_get_realm_domain", retval, 0);
		return;
	}
	printf("krb5_get_realm_domain(%s) returned '%s'\n", realm, domain);
	free(domain);
}

void usage(progname)
	char	*progname;
{
	fprintf(stderr, "%s: Usage: %s [-d] [-k realm] [-r host] [-D realm]\n",
		progname, progname);
	exit(1);
}

main(argc, argv)
	int	argc;
	char	**argv;
{
	int	c;
	krb5_context	ctx;
	krb5_error_code	retval;
	extern char *optarg;

	retval = krb5_init_context(&ctx);
	if (retval) {
		fprintf(stderr, "krb5_init_context returned error %ld\n",
			retval);
		exit(1);
	}

	while ((c = getopt(argc, argv, "dk:r:D:l:s:")) != -1) {
	    switch (c) {
	    case 'd': /* Get default realm */
		test_get_default_realm(ctx);
		break;
	    case 'k': /* Get list of KDC's */
		test_get_krbhst(ctx, optarg);
		break;
	    case 'l':
		test_locate_kdc(ctx, optarg);
		break;
	    case 'r':
		test_get_host_realm(ctx, optarg);
		break;
	    case 's':
		test_set_default_realm(ctx, optarg);
		break;
	    case 'D':
		test_get_realm_domain(ctx, optarg);
		break;
	    default:
		usage(argv[0]);
	    }
	}


	krb5_free_context(ctx);
	exit(0);
}
