/*
 * -DBSD_DES will test the BSD DES library.
 * without, it will test the MIT DES implementation.
 */

#ifndef BSD_DES
#include <krb5/krb5.h>
#include <krb5/mit-des.h>
#include <krb5/ext-proto.h>
#include <com_err.h>

extern int errno;
extern krb5_cryptosystem_entry mit_des_cryptosystem_entry;
extern mit_des_ecb_encrypt();
#endif

#include <stdio.h>


void convert();

void
main(argc, argv)
int argc;
char *argv[];
{
    char block1[17], block2[17], block3[17];

#ifdef BSD_DES
    char oldkey[65], oldinput[65], oldoutput[65];
#else
    krb5_encrypt_block eblock;
    krb5_keyblock keyblock;
    mit_des_cblock key, input, output, output2;
    krb5_error_code retval;
#endif

    int error = 0;

#ifndef BSD_DES
    /* do some initialisation */
    initialize_krb5_error_table();

    eblock.crypto_entry = &mit_des_cryptosystem_entry;
    keyblock.keytype = KEYTYPE_DES;
    keyblock.length = sizeof (mit_des_cblock);
    keyblock.contents = (krb5_octet *)key;
#endif

    while (scanf("%16s %16s %16s", block1, block2, block3) == 3) {
#ifdef BSD_DES
	convert(block1, oldkey);
	convert(block2, oldinput);
	convert(block3, oldoutput);
	setkey(oldkey);
	encrypt(oldinput, 0);
	if (strncmp(oldinput, oldoutput, 64)) {
	    fprintf(stderr, 
		    "DES ERROR, key %s, text %s\n\treal cipher %s\n\tcomputed %s\n",
		    block1, block2, oldoutput, oldinput);
	    error++;
	}
#else
	convert(block1, key);
	convert(block2, input);
	convert(block3, output);

        if (retval = krb5_process_key(&eblock,&keyblock)) {
            com_err("des test", retval, "can't process key");
            exit(-1);
        }
	mit_des_ecb_encrypt(input, output2,
			    (struct mit_des_ks_struct *)eblock.priv,1);

	if (bcmp((char *)output2, (char *)output, 8)) {
	    fprintf(stderr, 
		    "DES ERROR, key %s, text %s, real cipher %s, computed %02X%02X%02X%02X%02X%02X%02X%02X\n",
		    block1, block2, block3,
		    output2[0],output2[1],output2[2],output2[3],
		    output2[4],output2[5],output2[6],output2[7]);
	    error++;
	}

        if (retval = krb5_finish_key(&eblock)) {
            com_err("des verify", retval, "can't finish key");
            exit(-1);
        }
#endif
    }

    if (error) 
	printf("destest: failed to pass the test\n");
    else
	printf("destest: test is passed successfully\n");

    exit( (error > 256 && error % 256) ? 1 : error);
}

unsigned int value[128] = {
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
0, 1, 2, 3, 4, 5, 6, 7,
8, 9, -1, -1, -1, -1, -1, -1,
-1, 10, 11, 12, 13, 14, 15, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1,
};

#ifdef BSD_DES
char *value2[16] = {
    "0000", "0001", "0010", "0011",
    "0100", "0101", "0110", "0111",
    "1000", "1001", "1010", "1011",
    "1100", "1101", "1110", "1111",
};

void
convert(text, cblock)
char *text;
char cblock[];
{
    register int i;
    for (i = 0; i < 16; i++) {
	if (value[text[i]] == -1) {
	    printf("Bad value nybble %d in %s\n", i, text);
	    exit(1);
	}
	bcopy(value2[value[text[i]]], &cblock[i*4], 4);
    }
    cblock[64] = 0;
    return;
}

#else
void
convert(text, cblock)
char *text;
unsigned char cblock[];
{
    register int i;
    for (i = 0; i < 8; i++) {
	if (value[text[i*2]] == -1 || value[text[i*2+1]] == -1) {
	    printf("Bad value byte %d in %s\n", i, text);
	    exit(1);
	}
	cblock[i] = 16*value[text[i*2]] + value[text[i*2+1]];
    }
    return;
}
#endif

#ifndef BSD_DES
int
mit_des_is_weak_key(key)
    mit_des_cblock key;
{
    return 0;				/* fake it out for testing */
}
#endif

#ifndef __STDC__
#define const
#endif

#ifndef BSD_DES
#include "odd.h"

void
des_cblock_print_file(x, fp)
    mit_des_cblock x;
    FILE *fp;
{
    unsigned char *y = (unsigned char *) x;
    register int i = 0;
    fprintf(fp," 0x { ");

    while (i++ < 8) {
        fprintf(fp,"%x",*y++);
        if (i < 8)
            fprintf(fp,", ");
    }
    fprintf(fp," }");
}

int
des_check_key_parity(key)
    register mit_des_cblock key;
{
    int i;

    for (i=0; i<sizeof(mit_des_cblock); i++)
      if (key[i] != odd_parity[key[i]]) {
	  printf("warning: bad parity key:");
	  des_cblock_print_file(key, stdout); 
	  putchar('\n');
	  return(1);
      }
    return(1);
}

#endif
