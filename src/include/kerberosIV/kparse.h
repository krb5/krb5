/*
 * include/kerberosIV/kparse.h
 *
 * Copyright 1988, 1994 by the Massachusetts Institute of Technology.
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
 * Include file for kparse routines.
 */

#ifndef KPARSE_DEFS
#define KPARSE_DEFS

/*
 * values returned by fGetParameterSet() 
 */

#define PS_BAD_KEYWORD	  -2	/* unknown or duplicate keyword */
#define PS_SYNTAX	  -1	/* syntax error */
#define PS_OKAY		   0	/* got a complete parameter set */
#define PS_EOF		   1	/* nothing more in the file */

/*
 * values returned by fGetKeywordValue() 
 */

#define KV_SYNTAX	 -2	/* syntax error */
#define KV_EOF		 -1	/* nothing more in the file */
#define KV_OKAY		  0	/* got a keyword/value pair */
#define KV_EOL		  1	/* nothing more on this line */

/*
 * values returned by fGetToken() 
 */

#define GTOK_BAD_QSTRING -1	/* newline found in quoted string */
#define GTOK_EOF	  0	/* end of file encountered */
#define GTOK_QSTRING	  1	/* quoted string */
#define GTOK_STRING	  2	/* unquoted string */
#define GTOK_NUMBER	  3	/* one or more digits */
#define GTOK_PUNK	  4	/* punks are punctuation, newline,
				 * etc. */
#define GTOK_WHITE	  5	/* one or more whitespace chars */

/*
 * extended character classification macros 
 */

#define ISOCTAL(CH) 	( (CH>='0')  && (CH<='7') )
#define ISQUOTE(CH) 	( (CH=='\"') || (CH=='\'') || (CH=='`') )
#define ISWHITESPACE(C) ( (C==' ')   || (C=='\t') )
#define ISLINEFEED(C) 	( (C=='\n')  || (C=='\r')  || (C=='\f') )

/*
 * tokens consist of any printable charcacter except comma, equal, or
 * whitespace 
 */

#define ISTOKENCHAR(C) ((C>040) && (C<0177) && (C != ',') && (C != '='))

/*
 * the parameter table defines the keywords that will be recognized by
 * fGetParameterSet, and their default values if not specified. 
 */

typedef struct {
    char *keyword;
    char *defvalue;
    char *value;
}       parmtable;

#define PARMCOUNT(P) (sizeof(P)/sizeof(P[0]))

int fGetChar (FILE *fp);
int fGetParameterSet (FILE *fp, parmtable parm[], int parmcount);
int ParmCompare (parmtable parm[], int parmcount, char *keyword, char *value);

void FreeParameterSet (parmtable parm[], int parmcount);

int fGetKeywordValue (FILE *fp, char *keyword, int klen, char *value, int vlen);

int fGetToken (FILE *fp, char *dest, int maxlen);

int fGetLiteral (FILE *fp);

int fUngetChar (int ch, FILE *fp);

#endif /* KPARSE_DEFS */
