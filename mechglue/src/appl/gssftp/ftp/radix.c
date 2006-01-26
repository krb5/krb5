#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "ftp_var.h"

static char *radixN =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char pad = '=';

int radix_encode(inbuf, outbuf, len, decode)
unsigned char inbuf[], outbuf[];
int *len, decode;
{
	int i,j,D = 0;
	char *p;
	unsigned char c = 0;

	if (decode) {
		for (i=0,j=0; inbuf[i] && inbuf[i] != pad; i++) {
		    if ((p = strchr(radixN, inbuf[i])) == NULL) return(1);
		    D = p - radixN;
		    switch (i&3) {
			case 0:
			    c = D<<2;
			    break;
			case 1:
			    outbuf[j++] = c | D>>4;
			    c = (D&15)<<4;
			    break;
			case 2:
			    outbuf[j++] = c | D>>2;
			    c = (D&3)<<6;
			    break;
			case 3:
			    outbuf[j++] = c | D;
		    }
		}
		switch (i&3) {
			case 1: return(3);
			case 2: if (D&15) return(3);
				if (strcmp((char *)&inbuf[i], "==")) return(2);
				break;
			case 3: if (D&3) return(3);
				if (strcmp((char *)&inbuf[i], "="))  return(2);
		}
		*len = j;
	} else {
		for (i=0,j=0; i < *len; i++)
		    switch (i%3) {
			case 0:
			    outbuf[j++] = radixN[inbuf[i]>>2];
			    c = (inbuf[i]&3)<<4;
			    break;
			case 1:
			    outbuf[j++] = radixN[c|inbuf[i]>>4];
			    c = (inbuf[i]&15)<<2;
			    break;
			case 2:
			    outbuf[j++] = radixN[c|inbuf[i]>>6];
			    outbuf[j++] = radixN[inbuf[i]&63];
			    c = 0;
		    }
		if (i%3) outbuf[j++] = radixN[c];
		switch (i%3) {
			case 1: outbuf[j++] = pad;
			case 2: outbuf[j++] = pad;
		}
		outbuf[*len = j] = '\0';
	}
	return(0);
}

char *
radix_error(e)
int e;
{
	switch (e) {
	    case 0:  return("Success");
	    case 1:  return("Bad character in encoding");
	    case 2:  return("Encoding not properly padded");
	    case 3:  return("Decoded # of bits not a multiple of 8");
	    default: return("Unknown error");
	}
}

#ifdef STANDALONE
usage(s)
char *s;
{
	fprintf(stderr, "Usage: %s [ -d ] [ string ]\n", s);
	exit(2);
}

static int n;

putbuf(inbuf, outbuf, len, decode)
unsigned char inbuf[], outbuf[];
int len, decode;
{
	int c;

	if (c = radix_encode(inbuf, outbuf, &len, decode)) {
		fprintf(stderr, "Couldn't %scode input: %s\n",
				decode ? "de" : "en", radix_error(c));
		exit(1);
	}
	if (decode)
		write(1, outbuf, len);
	else
		for (c = 0; c < len;) {
			putchar(outbuf[c++]);
			if (++n%76 == 0) putchar('\n');
		}
}

main(argc,argv)
int argc;
char *argv[];
{
	unsigned char *inbuf, *outbuf;
	int c, len = 0, decode = 0;
	extern int optind;

	while ((c = getopt(argc, argv, "d")) != -1)
		switch(c) {
			default:
				usage(argv[0]);
			case 'd':
				decode++;
		}

	switch (argc - optind) {
		case 0:
			inbuf  = (unsigned char *) malloc(5);
			outbuf = (unsigned char *) malloc(5);
			while ((c = getchar()) != EOF)
			    if (c != '\n') {
				inbuf[len++] = c;
				if (len == (decode ? 4 : 3)) {
					inbuf[len] = '\0';
					putbuf(inbuf, outbuf, len, decode);
					len=0;
				}
			    }
			if (len) {
				inbuf[len] = '\0';
				putbuf(inbuf, outbuf, len, decode);
			}
			break;
		case 1:
			inbuf = (unsigned char *)argv[optind];
			len = strlen(inbuf);
			outbuf = (unsigned char *)
				malloc((len * (decode?3:4)) / (decode?4:3) + 1);
			putbuf(inbuf, outbuf, len, decode);
			break;
		default:
			fprintf(stderr, "Only one argument allowed\n");
			usage(argv[0]);
	}
	if (n%76) putchar('\n');
	exit(0);
}
#endif /* STANDALONE */
