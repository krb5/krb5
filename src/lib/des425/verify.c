/*
 * $Source$
 * $Author$
 *
 * Copyright 1988,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Program to test the correctness of the DES library
 * implementation.
 *
 * exit returns	 0 ==> success
 * 		-1 ==> error
 */

#ifndef	lint
static char rcsid_verify_c[] =
"$Id$";
#endif	lint

#include <stdio.h>
#include <errno.h>
#include "./des.h"

extern char *errmsg();
extern int errno;
extern int des_string_to_key();
extern int des_key_sched();
extern int des_ecb_encrypt();
extern int des_cbc_encrypt();
extern exit();
char *progname;
int nflag = 2;
int vflag;
int mflag;
int zflag;
int pid;
int des_debug;
des_key_schedule KS;
unsigned char cipher_text[64];
unsigned char clear_text[64] = "Now is the time for all " ;
unsigned char clear_text2[64] = "7654321 Now is the time for ";
unsigned char clear_text3[64] = {2,0,0,0, 1,0,0,0};
unsigned char output[64];
unsigned char zero_text[8] = {0x0,0,0,0,0,0,0,0};
unsigned char msb_text[8] = {0x0,0,0,0, 0,0,0,0x40}; /* to ANSI MSB */
unsigned char *input;

/* 0x0123456789abcdef */
unsigned char default_key[8] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};
unsigned char key2[8] = { 0x08,0x19,0x2a,0x3b,0x4c,0x5d,0x6e,0x7f };
unsigned char key3[8] = { 0x80,1,1,1,1,1,1,1 };
des_cblock s_key;
unsigned char default_ivec[8] = {
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
};
unsigned char *ivec;
unsigned char zero_key[8] = {1,1,1,1,1,1,1,1}; /* just parity bits */
int i,j;

/*
 * Can also add :
 * plaintext = 0, key = 0, cipher = 0x8ca64de9c1b123a7 (or is it a 1?)
 */

main(argc,argv)
    int argc;
    char *argv[];
{
    /* Local Declarations */
    long in_length;

    progname=argv[0];		/* salt away invoking program */

    /* Assume a long is four bytes */
    if (sizeof(long) != 4) {
	printf("\nERROR,  size of long is %d",sizeof(long));
	exit(-1);
    }

    while (--argc > 0 && (*++argv)[0] == '-')
	for (i=1; argv[0][i] != '\0'; i++) {
	    switch (argv[0][i]) {

		/* debug flag */
	    case 'd':
		des_debug=3;
		continue;

	    case 'z':
		zflag = 1;
		continue;

	    case 'm':
		mflag = 1;
		continue;

	    default:
		printf("%s: illegal flag \"%c\" ",
		       progname,argv[0][i]);
		exit(1);
	    }
	};

    if (argc) {
	fprintf(stderr, "Usage: %s [-dmz]\n", progname);
	exit(1);
    }

    /* use known input and key */

    /* ECB zero text zero key */
    if (zflag) {
	input = zero_text;
	des_key_sched(zero_key,KS);
	printf("plaintext = key = 0, cipher = 0x8ca64de9c1b123a7\n");
	do_encrypt(input,cipher_text);
	printf("\tcipher  = (low to high bytes)\n\t\t");
	for (j = 0; j<=7; j++)
	    printf("%02x ",cipher_text[j]);
	printf("\n");
	do_decrypt(output,cipher_text);
	return(0);
    }

    if (mflag) {
	input = msb_text;
	des_key_sched(key3,KS);
	printf("plaintext = 0x00 00 00 00 00 00 00 40, ");
	printf("key = 0, cipher = 0x??\n");
	do_encrypt(input,cipher_text);
	printf("\tcipher  = (low to high bytes)\n\t\t");
	for (j = 0; j<=7; j++) {
	    printf("%02x ",cipher_text[j]);
	}
	printf("\n");
	do_decrypt(output,cipher_text);
	return(0);
    }

    /* ECB mode Davies and Price */
    {
	input = zero_text;
	des_key_sched(key2,KS);
	printf("Examples per FIPS publication 81, keys ivs and cipher\n");
	printf("in hex.  These are the correct answers, see below for\n");
	printf("the actual answers.\n\n");
	printf("Examples per Davies and Price.\n\n");
	printf("EXAMPLE ECB\tkey = 08192a3b4c5d6e7f\n");
	printf("\tclear = 0\n");
	printf("\tcipher = 25 dd ac 3e 96 17 64 67\n");
	printf("ACTUAL ECB\n");
	printf("\tclear \"%s\"\n", input);
	do_encrypt(input,cipher_text);
	printf("\tcipher  = (low to high bytes)\n\t\t");
	for (j = 0; j<=7; j++)
	    printf("%02x ",cipher_text[j]);
	printf("\n\n");
	do_decrypt(output,cipher_text);
    }

    /* ECB mode */
    {
	des_key_sched(default_key,KS);
	input = clear_text;
	ivec = default_ivec;
	printf("EXAMPLE ECB\tkey = 0123456789abcdef\n");
	printf("\tclear = \"Now is the time for all \"\n");
	printf("\tcipher = 3f a4 0e 8a 98 4d 48 15 ...\n");
	printf("ACTUAL ECB\n\tclear \"%s\"",input);
	do_encrypt(input,cipher_text);
	printf("\n\tcipher	= (low to high bytes)\n\t\t");
	for (j = 0; j<=7; j++) {
	    printf("%02x ",cipher_text[j]);
	}
	printf("\n\n");
	do_decrypt(output,cipher_text);
    }

    /* CBC mode */
    printf("EXAMPLE CBC\tkey = 0123456789abcdef");
    printf("\tiv = 1234567890abcdef\n");
    printf("\tclear = \"Now is the time for all \"\n");
    printf("\tcipher =\te5 c7 cd de 87 2b f2 7c\n");
    printf("\t\t\t43 e9 34 00 8c 38 9c 0f\n");
    printf("\t\t\t68 37 88 49 9a 7c 05 f6\n");

    printf("ACTUAL CBC\n\tclear \"%s\"\n",input);
    in_length = strlen(input);
    des_cbc_encrypt(input,cipher_text,(long) in_length,KS,ivec,1);
    printf("\tciphertext = (low to high bytes)\n");
    for (i = 0; i <= 7; i++) {
	printf("\t\t");
	for (j = 0; j <= 7; j++) {
	    printf("%02x ",cipher_text[i*8+j]);
	}
	printf("\n");
    }
    des_cbc_encrypt(cipher_text,clear_text,(long) in_length,KS,ivec,0);
    printf("\tdecrypted clear_text = \"%s\"\n",clear_text);

    printf("EXAMPLE CBC checksum");
    printf("\tkey =  0123456789abcdef\tiv =  1234567890abcdef\n");
    printf("\tclear =\t\t\"7654321 Now is the time for \"\n");
    printf("\tchecksum\t58 d2 e7 7e 86 06 27 33, ");
    printf("or some part thereof\n");
    input = clear_text2;
    des_cbc_cksum(input,cipher_text,(long) strlen(input),KS,ivec,1);
    printf("ACTUAL CBC checksum\n");
    printf("\t\tencrypted cksum = (low to high bytes)\n\t\t");
    for (j = 0; j<=7; j++)
	printf("%02x ",cipher_text[j]);
    printf("\n\n");
    exit(0);
}

flip(array)
    char *array;
{
    register old,new,i,j;
    /* flips the bit order within each byte from 0 lsb to 0 msb */
    for (i = 0; i<=7; i++) {
	old = *array;
	new = 0;
	for (j = 0; j<=7; j++) {
	    if (old & 01)
		new = new | 01;
	    if (j < 7) {
		old = old >> 1;
		new = new << 1;
	    }
	}
	*array = new;
	array++;
    }
}

do_encrypt(in,out)
    char *in;
    char *out;
{
    for (i =1; i<=nflag; i++) {
	des_ecb_encrypt(in,out,KS,1);
	if (des_debug) {
	    printf("\nclear %s\n",in);
	    for (j = 0; j<=7; j++)
		printf("%02 X ",in[j] & 0xff);
	    printf("\tcipher ");
	    for (j = 0; j<=7; j++)
		printf("%02X ",out[j] & 0xff);
	}
    }
}

do_decrypt(in,out)
    char *out;
    char *in;
    /* try to invert it */
{
    for (i =1; i<=nflag; i++) {
	des_ecb_encrypt(out,in,KS,0);
	if (des_debug) {
	    printf("clear %s\n",in);
	    for (j = 0; j<=7; j++)
		printf("%02X ",in[j] & 0xff);
	    printf("\tcipher ");
	    for (j = 0; j<=7; j++)
		printf("%02X ",out[j] & 0xff);
	}
    }
}
