#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int inlen, outlen, i;
    unsigned char *instr, *outstr;

    if (argc != 3) {
	fprintf(stderr, "%s: instr outlen\n", argv[0]);
	exit(1);
    }

    instr = (unsigned char *) argv[1];
    inlen = strlen(instr)*8;
    outlen = atoi(argv[2]);
    if (outlen%8) {
	fprintf(stderr, "outlen must be a multiple of 8\n");
	exit(1);
    }

    if ((outstr = (unsigned char *) malloc(outlen/8)) == NULL) {
	fprintf(stderr, "ENOMEM\n");
	exit(1);
    }

    krb5_nfold(inlen,instr,outlen,outstr);

    printf("%d-fold(",outlen);
    for (i=0; i<(inlen/8); i++)
	printf("%02x",instr[i]);
    printf(") = ");
    for (i=0; i<(outlen/8); i++)
	printf("%02x",outstr[i]);
    printf("\n");

    exit(0);
}
