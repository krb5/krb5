/*
 * lib/krb5/krb/deltat.y
 *
 * Copyright 1999 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_string_to_deltat()
 */

/* For a clean, thread-safe interface, we must use the "pure parser"
   facility of GNU Bison.  Unfortunately, standard YACC has no such
   option.  */

/* N.B.: For simplicity in dealing with the distribution, the
   Makefile.in listing for deltat.c does *not* normally list this
   file.  If you change this file, tweak the Makefile so it'll rebuild
   deltat.c, or do it manually.  */
%{

#include <ctype.h>
#include <errno.h>
#include "k5-int.h"

struct param {
    krb5_deltat delta;
    char *p;
};

#define YYPARSE_PARAM tmv

#define DO(D,H,M,S) \
 { \
     ((struct param *)tmv)->delta = (((D * 24) + H) * 60 + M) * 60 + S; \
 }

static int mylex (int *, char **);
#define YYLEX_PARAM (&((struct param *)tmv)->p)
#undef yylex
#define yylex(U, P)    mylex (&(U)->val, (P))

#undef yyerror
#define yyerror(MSG)

static int yyparse (void *);

%}

%pure_parser

%union { int val; }

%token <val> NUM LONGNUM
%token '-' ':' 'd' 'h' 'm' 's' WS

%type <val> num opt_hms opt_ms opt_s wsnum posnum

%start start

%%

start: deltat ;
posnum: NUM | LONGNUM ;
num: posnum | '-' posnum { $$ = - $2; } ;
ws: /* nothing */ | WS ;
wsnum: ws num { $$ = $2; };
deltat:
	  wsnum 'd' opt_hms			{ DO ($1,  0,  0, $3); }
	| wsnum 'h' opt_ms			{ DO ( 0, $1,  0, $3); }
	| wsnum 'm' opt_s			{ DO ( 0,  0, $1, $3); }
	| wsnum 's'				{ DO ( 0,  0,  0, $1); }
	| wsnum '-' NUM ':' NUM ':' NUM		{ DO ($1, $3, $5, $7); }
	| wsnum ':' NUM ':' NUM			{ DO ( 0, $1, $3, $5); }
	| wsnum ':' NUM				{ DO ( 0, $1, $3,  0); }
	;

opt_hms:
	  opt_ms
	| wsnum 'h' opt_ms			{ $$ = $1 * 3600 + $3; };
opt_ms:
	  opt_s
	| wsnum 'm' opt_s			{ $$ = $1 * 60 + $3; };
opt_s:
	  ws					{ $$ = 0; }
	| wsnum 's' ;

%%

static int
mylex (int *intp, char **pp)
{
    int num, c;
#define P (*pp)
    char *orig_p = P;

#ifdef isascii
    if (!isascii (*P))
	return 0;
#endif
    switch (c = *P++) {
    case '-':
    case ':':
    case 'd':
    case 'h':
    case 'm':
    case 's':
	return c;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
	/* XXX assumes ASCII */
	num = c - '0';
	while (isdigit (*P)) {
	    num *= 10;
	    num += *P++ - '0';
	}
	*intp = num;
	return (P - orig_p > 2) ? LONGNUM : NUM;
    case ' ':
    case '\t':
    case '\n':
	while (isspace (*P))
	    P++;
	return WS;
    default:
	return YYEOF;
    }
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_deltat(string, deltatp)
    char	FAR * string;
    krb5_deltat	FAR * deltatp;
{
    struct param p;
    p.delta = 0;
    p.p = string;
    if (yyparse (&p))
	return EINVAL;
    *deltatp = p.delta;
    return 0;
}
