/*
 * This driver routine is used to test many of the standard Kerberos library
 * routines.
 */

#include "krb5.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "com_err.h"


void test_425_conv_principal(ctx, name, inst, realm)
    krb5_context ctx;
    char *name, *inst, *realm;
{
    krb5_error_code	retval;
    krb5_principal	princ;

    retval = krb5_425_conv_principal(ctx, name, inst, realm, &princ);
    if (retval) {
	com_err("krb5_425_conv_principal", retval, 0);
	return;
    }
    retval = krb5_unparse_name(ctx, princ, &name);
    printf("425_converted principal: '%s'\n", name);
    free(name);
    krb5_free_principal(ctx, princ);
}

void usage(progname)
	char	*progname;
{
	fprintf(stderr, "%s: Usage: %s [425_conv_principal <name> <inst> <realm]\n",
		progname, progname);
	exit(1);
}

int 
main(argc, argv)
     int argc;
     char **argv;
{
    krb5_context ctx;
    krb5_error_code retval;
    char *progname;
    char *name, *inst, *realm;

    retval = krb5_init_context(&ctx);
    if (retval) {
	fprintf(stderr, "krb5_init_context returned error %ld\n",
		retval);
	exit(1);
    }
    krb5_init_ets(ctx);
    progname = argv[0];

     /* Parse arguments. */
     argc--; argv++;
     while (argc) {
	 if (strcmp(*argv, "425_conv_principal") == 0) {
	     argc--; argv++;
	     if (!argc) usage(progname);
	     name = *argv;
	     argc--; argv++;
	     if (!argc) usage(progname);
	     inst = *argv;
	     argc--; argv++;
	     if (!argc) usage(progname);
	     realm = *argv;
	     test_425_conv_principal(ctx, name, inst, realm);
	  } else
	      usage(progname);
	  argc--; argv++;
     }

    krb5_free_context(ctx);

    return 0;
}
