#include "krb5.h"

#include <stdio.h>

void test_realm_iterator(int ctx)
{
    krb5_error_code retval;
    char *realm;
    void *iter;

    if ((retval = krb5_realm_iterator_create(ctx, &iter))) {
	com_err("krb5_realm_iterator_create", retval, 0);
	return;
    }
    while (iter) {
	if ((retval = krb5_realm_iterator(ctx, &iter, &realm))) {
	    com_err("krb5_realm_iterator", retval, 0);
	    krb5_realm_iterator_free(ctx, &iter);
	    return;
	}
	if (realm) {
	    printf("Realm: '%s'\n", realm);
	    krb5_free_realm_string(ctx, realm);
	}
    }
}

int main(int argc, char **argv)
{
    krb5_context ctx;
    krb5_error_code retval;

    retval = krb5_init_context(&ctx);
    if (retval) {
	fprintf(stderr, "krb5_init_context returned error %ld\n",
		retval);
	exit(1);
    }

    test_realm_iterator(ctx);

    krb5_free_context(ctx);
    return 0;
}
