/*
 * Copyright (C) 1992,1993 Trusted Information Systems, Inc.
 *
 * Permission to include this software in the Kerberos V5 distribution
 * was graciously provided by Trusted Information Systems.
 * 
 * Trusted Information Systems makes no representation about the
 * suitability of this software for any purpose.  It is provided
 * "as is" without express or implied warranty.
 * 
 * Copyright (C) 1994 Massachusetts Institute of Technology
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
 */

/*****************************************************************************
 * trval.c.c
 *****************************************************************************/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

extern char *malloc(), *realloc();

#define OK 0
#define NOTOK (-1)
	
	/* IDENTIFIER OCTET = TAG CLASS | FORM OF ENCODING | TAG NUMBER */
	
	/* TAG CLASSES */
#define ID_CLASS   0xc0		/* bits 8 and 7 */
#define CLASS_UNIV 0x00		/* 0 = universal */
#define CLASS_APPL 0x40		/* 1 = application */
#define CLASS_CONT 0x80		/* 2 = context-specific */
#define CLASS_PRIV 0xc0		/* 3 = private */
	
	/* FORM OF ENCODING */
#define ID_FORM   0x20		/* bit 6 */
#define FORM_PRIM 0x00		/* 0 = primitive */
#define FORM_CONS 0x20		/* 1 = constructed */
	
	/* TAG NUMBERS */
#define ID_TAG    0x1f		/* bits 5-1 */
#define PRIM_BOOL 0x01		/* Boolean */
#define PRIM_INT  0x02		/* Integer */
#define PRIM_BITS 0x03		/* Bit String */
#define PRIM_OCTS 0x04		/* Octet String */
#define PRIM_NULL 0x05		/* Null */
#define PRIM_OID  0x06		/* Object Identifier */
#define PRIM_ODE  0x07		/* Object Descriptor */
#define CONS_EXTN 0x08		/* External */
#define PRIM_REAL 0x09		/* Real */
#define PRIM_ENUM 0x0a		/* Enumerated type */
#define PRIM_ENCR 0x0b		/* Encrypted */
#define CONS_SEQ  0x10		/* SEQUENCE/SEQUENCE OF */
#define CONS_SET  0x11		/* SET/SET OF */
#define DEFN_NUMS 0x12		/* Numeric String */
#define DEFN_PRTS 0x13		/* Printable String */
#define DEFN_T61S 0x14		/* T.61 String */
#define DEFN_VTXS 0x15		/* Videotex String */
#define DEFN_IA5S 0x16		/* IA5 String */
#define DEFN_UTCT 0x17		/* UTCTime */
#define DEFN_GENT 0x18		/* Generalized Time */
#define DEFN_GFXS 0x19		/* Graphics string (ISO2375) */
#define DEFN_VISS 0x1a		/* Visible string */
#define DEFN_GENS 0x1b		/* General string */
#define DEFN_CHRS 0x1c		/* Character string */
	
#define	LEN_XTND	0x80	/* long or indefinite form */
#define	LEN_SMAX	127	/* largest short form */
#define	LEN_MASK	0x7f	/* mask to get number of bytes in length */
#define	LEN_INDF	(-1)	/* indefinite length */

#define KRB5	/* Do krb5 application types */
	
int print_types = 0;
int print_id_and_len = 1;
int print_constructed_length = 1;	
int print_primitive_length = 1;
int print_skip_context = 0;
int print_skip_tagnum = 0;
int print_context_shortcut = 0;
#ifdef KRB5
int print_krb5_types = 0;
int print_skip_krb5_tagnum = 0;
#endif

void print_tag_type();
int trval(), trval2(), decode_len(), do_cons(), do_prim();

/****************************************************************************/

#ifdef STANDALONE

int main(argc, argv)
	int argc;
	char **argv;
{
	int optflg = 1;
	FILE *fp;
	int r;
	
	while (--argc > 0) {
		argv++;
		if (optflg && *(argv)[0] == '-') {
			if (!strcmp(*argv,"-types"))
				print_types = 1;
			else if (!strcmp(*argv,"-notypes"))
				print_types = 0;
			else {
				fprintf(stderr,"trval: unknown option: %s\n", *argv);
				exit(1);
			}
		} else {
			optflg = 0;
			if ((fp = fopen(*argv,"r")) == NULL) {
				fprintf(stderr,"trval: unable to open %s\n", *argv);
				continue;
			}
			r = trval(fp, stdout);
			fclose(fp);
		}
	}
	if (optflg) r = trval(stdin, stdout);
	
	exit(r);
}
#endif

int trval(fin, fout)
	FILE	*fin;
	FILE	*fout;
{
	unsigned char *p;
	int maxlen;
	int len;
	int cc;
	int r;
	int rlen;
	
	maxlen = BUFSIZ;
	p = (unsigned char *)malloc(maxlen);
	len = 0;
	while ((cc = fgetc(fin)) != EOF) {
		if (len == maxlen) {
			maxlen += BUFSIZ;
			p = (unsigned char *)realloc(p, maxlen);
		}
		p[len++] = cc;
	}
	fprintf(fout, "<%d>", len);
	r = trval2(fout, p, len, 0, &rlen);
	fprintf(fout, "\n");
	(void) free(p);
	return(r);
}

int trval2(fp, enc, len, lev, rlen)
	FILE *fp;
	unsigned char *enc;
	int len;
	int lev;
	int *rlen;
{
	int l, eid, elen, xlen, r, rlen2;
	int rlen_ext = 0;
	

	if (len < 2) {
		fprintf(fp, "missing id and length octets (%d)\n", len);
		return(NOTOK);
	}
	
	fprintf(fp, "\n");
	for (l=0; l<lev; l++) fprintf(fp, ".  ");
	
context_restart:
	eid = enc[0];
	elen = enc[1];

	if (print_id_and_len) {
		fprintf(fp, "%02x ", eid);
		fprintf(fp, "%02x ", elen);
	}
	
	if (elen == LEN_XTND) {
		fprintf(fp,
			"indefinite length encoding not implemented (0x%02x)\n", elen);
		return(NOTOK);
	}
	
	xlen = 0;
	if (elen & LEN_XTND) {
		xlen = elen & LEN_MASK;
		if (xlen > len - 2) {
			fprintf(fp, "extended length too long (%d > %d - 2)\n", xlen, len);
			return(NOTOK);
		}
		elen = decode_len(fp, enc+2, xlen);
	}
	
	if (elen > len - 2 - xlen) {
		fprintf(fp, "length too long (%d > %d - 2 - %d)\n", elen, len, xlen);
		return(NOTOK);
	}
	
	print_tag_type(fp, eid, lev);

	if (print_context_shortcut &&
	    ((eid & ID_CLASS) == CLASS_CONT) && (lev > 0)) {
		rlen_ext += 2 + xlen;
		enc += 2 + xlen;
		goto context_restart;
	}

	switch(eid & ID_FORM) {
	case FORM_PRIM:
		if (print_primitive_length)
			fprintf(fp, "<%d>", elen);
		r = do_prim(fp, eid & ID_TAG, enc+2+xlen, elen, lev+1);
		*rlen = 2 + xlen + elen + rlen_ext;
		break;
	case FORM_CONS:
		if (print_constructed_length) {
			fprintf(fp, "constr ");
			fprintf(fp, "<%d>", elen);
		}
		r = do_cons(fp, enc+2+xlen, elen, lev+1, &rlen2);
		*rlen = 2 + xlen + rlen2 + rlen_ext;
		break;
	}
	
	return(r);
}

int decode_len(fp, enc, len)
	FILE *fp;
	unsigned char *enc;
	int len;
{
	int rlen;
	int i;
	
	if (print_id_and_len)
		fprintf(fp, "%02x ", enc[0]);
	rlen = enc[0];
	for (i=1; i<len; i++) {
		if (print_id_and_len)
			fprintf(fp, "%02x ", enc[i]);
		rlen = (rlen * 0x100) + enc[i];
	}
	return(rlen);
}

#define WIDTH 8

int do_prim(fp, tag, enc, len, lev)
	FILE *fp;
	int tag;
	unsigned char *enc;
	int len;
	int lev;
{
	int n;
	int i;
	int j;
	
	for (n = 0; n < len; n++) {
		if ((n % WIDTH) == 0) {
			fprintf(fp, "\n");
	    for (i=0; i<lev; i++) fprintf(fp, "   ");
	}
	fprintf(fp, "%02x ", enc[n]);
	if ((n % WIDTH) == (WIDTH-1)) {
	    fprintf(fp, "    ");
	    for (i=n-(WIDTH-1); i<=n; i++)
		if (isprint(enc[i])) fprintf(fp, "%c", enc[i]);
		else fprintf(fp, ".");
	}
    }
    if ((j = (n % WIDTH)) != 0) {
	fprintf(fp, "    ");
	for (i=0; i<WIDTH-j; i++) fprintf(fp, "   ");
	for (i=n-j; i<n; i++)
	    if (isprint(enc[i])) fprintf(fp, "%c", enc[i]);
	    else fprintf(fp, ".");
    }
    return(OK);
}

int do_cons(fp, enc, len, lev, rlen)
FILE *fp;
unsigned char *enc;
int len;
int lev;
int *rlen;
{
    int n;
    int r = 0;
    int rlen2;
    int rlent;

    for (n = 0, rlent = 0; n < len; n+=rlen2, rlent+=rlen2) {
	r = trval2(fp, enc+n, len-n, lev, &rlen2);
	if (r != OK) return(r);
    }
    if (rlent != len) {
	fprintf(fp, "inconsistent constructed lengths (%d != %d)\n",
	rlent, len);
	return(NOTOK);
    }
    *rlen = rlent;
    return(r);
}

void print_tag_type(fp, eid, lev)
	FILE *fp;
	int	eid;
	int	lev;
{
	int	tag = eid & ID_TAG;
	int	do_space = 1;

	fprintf(fp, "[");
	
	switch(eid & ID_CLASS) {
	case CLASS_UNIV:
		if (print_types && print_skip_tagnum)
			do_space = 0;
		else
			fprintf(fp, "UNIV %d", tag);
		break;
	case CLASS_APPL:
#ifdef KRB5
		if (print_krb5_types && print_skip_krb5_tagnum)
			do_space = 0;
		else
#endif
			fprintf(fp, "APPL %d", tag);
		break;
	case CLASS_CONT:
		if (print_skip_context && lev)
			fprintf(fp, "%d", tag);
		else
			fprintf(fp, "CONT %d", tag);
		break;
	case CLASS_PRIV:
		fprintf(fp, "PRIV %d", tag);
		break;
	}
	
	if (print_types && ((eid & ID_CLASS) == CLASS_UNIV)) {
		if (do_space)
			fprintf(fp, " ");
		switch(eid & ID_TAG) {
		case PRIM_BOOL: fprintf(fp, "Boolean"); break;
		case PRIM_INT:  fprintf(fp, "Integer"); break;
		case PRIM_BITS: fprintf(fp, "Bit String"); break;
		case PRIM_OCTS: fprintf(fp, "Octet String"); break;
		case PRIM_NULL: fprintf(fp, "Null"); break;
		case PRIM_OID:  fprintf(fp, "Object Identifier"); break;
		case PRIM_ODE:  fprintf(fp, "Object Descriptor"); break;
		case CONS_EXTN: fprintf(fp, "External"); break;
		case PRIM_REAL: fprintf(fp, "Real"); break;
		case PRIM_ENUM: fprintf(fp, "Enumerated type"); break;
		case PRIM_ENCR: fprintf(fp, "Encrypted"); break;
		case CONS_SEQ:  fprintf(fp, "Sequence/Sequence Of"); break;
		case CONS_SET:  fprintf(fp, "Set/Set Of"); break;
		case DEFN_NUMS: fprintf(fp, "Numeric String"); break;
		case DEFN_PRTS: fprintf(fp, "Printable String"); break;
		case DEFN_T61S: fprintf(fp, "T.61 String"); break;
		case DEFN_VTXS: fprintf(fp, "Videotex String"); break;
		case DEFN_IA5S: fprintf(fp, "IA5 String"); break;
		case DEFN_UTCT: fprintf(fp, "UTCTime"); break;
		case DEFN_GENT: fprintf(fp, "Generalized Time"); break;
		case DEFN_GFXS: fprintf(fp, "Graphics string (ISO2375)"); break;
		case DEFN_VISS: fprintf(fp, "Visible string"); break;
		case DEFN_GENS: fprintf(fp, "General string"); break;
		case DEFN_CHRS: fprintf(fp, "Character string"); break;
		default: fprintf(fp, "UNIV %d???", eid);
		}
	}
	
#ifdef KRB5
	if (print_krb5_types && ((eid & ID_CLASS) == CLASS_APPL)) {
		if (do_space)
			fprintf(fp, " ");
		switch(eid & ID_TAG) {
		case 1: fprintf(fp, "Krb5 Ticket"); break;
		case 2: fprintf(fp, "Krb5 Autenticator"); break;
		case 3: fprintf(fp, "Krb5 Encrypted ticket part"); break;
		case 10: fprintf(fp, "Krb5 AS-REQ packet"); break;
		case 11: fprintf(fp, "Krb5 AS-REP packet"); break;
		case 12: fprintf(fp, "Krb5 TGS-REQ packet"); break;
		case 13: fprintf(fp, "Krb5 TGS-REP packet"); break;
		case 14: fprintf(fp, "Krb5 AP-REQ packet"); break;
		case 15: fprintf(fp, "Krb5 AP-REP packet"); break;
		case 20: fprintf(fp, "Krb5 SAFE packet"); break;
		case 21: fprintf(fp, "Krb5 PRIV packet"); break;
		case 22: fprintf(fp, "Krb5 CRED packet"); break;
		case 30: fprintf(fp, "Krb5 ERROR packet"); break;
		case 25: fprintf(fp, "Krb5 Encrypted AS-REQ part"); break;
		case 26: fprintf(fp, "Krb5 Encrypted TGS-REQ part"); break;
		case 27: fprintf(fp, "Krb5 Encrypted AP-REP part"); break;
		case 28: fprintf(fp, "Krb5 Encrypted PRIV part"); break;
		case 29: fprintf(fp, "Krb5 Encrypted CRED part"); break;
		default: fprintf(fp, "APPL %d???", eid);
		}
	}
#endif

	fprintf(fp, "] ");
	
}	

/*****************************************************************************/

