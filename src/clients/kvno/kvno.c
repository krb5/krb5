#include <stdio.h>
#include <string.h>
#include <krb5.h>

extern int optind;
extern char *optarg;

void usage(char *argv0)
{
    char *cmd;

    cmd = strrchr(argv0, '/');
    cmd = cmd?(cmd+1):argv0;

    fprintf(stderr, "usage: %s [-e etype] service1 service2 ...\n", cmd);

    exit(1);
}

int main(int argc, char *argv[])
{
    krb5_context context;
    krb5_error_code ret;
    int option, i, errors;
    char *etypestr = 0;
    int quiet = 0;
    krb5_enctype etype;
    krb5_ccache ccache;
    krb5_principal me;
    krb5_creds in_creds, *out_creds;
    krb5_ticket *ticket;
    char *princ;

    if (ret = krb5_init_context(&context)) {
	com_err(argv[0], ret, "while initializing krb5 library");
	exit(1);
    }

    while ((option = getopt(argc, argv, "e:hq")) != -1) {
	switch (option) {
	case 'e':
	    etypestr = optarg;
	    break;
	case 'h':
	    usage(argv[0]);
	    break;
	case 'q':
	    quiet = 1;
	    break;
	default:
	    usage(argv[0]);
	    break;
	}
    }

    if ((argc - optind) < 1)
	usage(argv[0]);

    if (etypestr) {
	if (ret = krb5_string_to_enctype(etypestr, &etype)) {
	    com_err(argv[0], ret, "while converting etype");
	    exit(1);
	}
    } else {
	etype = 0;
    }

    if (ret = krb5_cc_default(context, &ccache)) {
	com_err(argv[0], ret, "while opening ccache");
	exit(1);
    }

    if (ret = krb5_cc_get_principal(context, ccache, &me)) {
	com_err(argv[0], ret, "while getting client principal name");
	exit(1);
    }

    errors = 0;

    for (i = optind; i < argc; i++) {
	memset(&in_creds, 0, sizeof(in_creds));

	in_creds.client = me;

	if (ret = krb5_parse_name(context, argv[i], &in_creds.server)) {
	    if (!quiet)
		fprintf(stderr, "%s: %s while parsing principal name\n",
			argv[i], error_message(ret));
	    errors++;
	    continue;
	}

	if (ret = krb5_unparse_name(context, in_creds.server, &princ)) {
	    fprintf(stderr, "%s: %s while printing principal name\n",
		    argv[i], error_message(ret));
	    errors++;
	    continue;
	}

	in_creds.keyblock.enctype = etype;

	ret = krb5_get_credentials(context, 0, ccache, &in_creds, &out_creds);

	krb5_free_principal(context, in_creds.server);

	if (ret) {
	    fprintf(stderr, "%s: %s while getting credentials\n",
		    princ, error_message(ret));

	    free(princ);

	    errors++;
	    continue;
	}

	/* we need a native ticket */
	if (ret = decode_krb5_ticket(&out_creds->ticket, &ticket)) {
	    fprintf(stderr, "%s: %s while decoding ticket\n",
		    princ, error_message(ret));

	    krb5_free_creds(context, out_creds);
	    free(princ);

	    errors++;
	    continue;
	}
	    
	if (!quiet)
	    printf("%s: kvno = %d\n", princ, ticket->enc_part.kvno);

	krb5_free_ticket(context, ticket);
	krb5_free_creds(context, out_creds);
	free(princ);
    }

    krb5_free_principal(context, me);
    krb5_cc_close(context, ccache);

    if (errors)
	exit(1);

    exit(0);
}
