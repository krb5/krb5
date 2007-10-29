// Test that the krb5.h header is compatible with C++ application code.

#include <stdio.h>
#include "krb5.h"

int main (int argc, char *argv[])
{
    krb5_context ctx;

    if (krb5_init_context(&ctx) != 0) {
	printf("krb5_init_context returned an error\n");
	return 1;
    }
    printf("hello, world\n");
    return 0;
}
