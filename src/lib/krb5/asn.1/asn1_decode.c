/*
 * src/lib/krb5/asn.1/asn1_decode.c
 * 
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/* ASN.1 primitive decoders */
#include "asn1_decode.h"
#include "asn1_get.h"
#include <stdio.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif

#define setup()\
asn1_error_code retval;\
asn1_class class;\
asn1_construction construction;\
asn1_tagnum tagnum;\
int length

#define tag(type)\
retval = asn1_get_tag(buf,&class,&construction,&tagnum,&length);\
if(retval) return retval;\
if(class != UNIVERSAL || construction != PRIMITIVE || tagnum != type)\
  return ASN1_BAD_ID
  
#define cleanup()\
return 0

time_t gmt_mktime PROTOTYPE((struct tm *));

asn1_error_code asn1_decode_integer(buf, val)
     asn1buf * buf;
     long * val;
{
  setup();
  asn1_octet o;
  long n;
  int i;

  tag(ASN1_INTEGER);

  for (i = 0; i < length; i++) {
    retval = asn1buf_remove_octet(buf, &o);
    if (retval) return retval;
    if (!i) {
      n = (0x80 & o) ? -1 : 0;	/* grab sign bit */
      if (n < 0 && length > sizeof (long))
	return ASN1_OVERFLOW;
      else if (length > sizeof (long) + 1) /* allow extra octet for positive */
	return ASN1_OVERFLOW;
    }
    n = (n << 8) | o;
  }
  *val = n;
  cleanup();
}

asn1_error_code asn1_decode_unsigned_integer(buf, val)
     asn1buf * buf;
     unsigned long * val;
{
  setup();
  asn1_octet o;
  unsigned long n;
  int i;

  tag(ASN1_INTEGER);

  for (i = 0, n = 0; i < length; i++) {
    retval = asn1buf_remove_octet(buf, &o);
    if(retval) return retval;
    if (!i) {
      if (0x80 & o)
	return ASN1_OVERFLOW;
      else if (length > sizeof (long) + 1)
	return ASN1_OVERFLOW;
    }
    n = (n << 8) | o;
  }
  *val = n;
  cleanup();
}

asn1_error_code asn1_decode_octetstring(buf, retlen, val)
     asn1buf * buf;
     int * retlen;
     asn1_octet ** val;
{
  setup();
  tag(ASN1_OCTETSTRING);
  retval = asn1buf_remove_octetstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_charstring(buf, retlen, val)
     asn1buf * buf;
     int * retlen;
     char ** val;
{
  setup();
  tag(ASN1_OCTETSTRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}


asn1_error_code asn1_decode_generalstring(buf, retlen, val)
     asn1buf * buf;
     int * retlen;
     char ** val;
{
  setup();
  tag(ASN1_GENERALSTRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}


asn1_error_code asn1_decode_null(buf)
     asn1buf * buf;
{
  setup();
  tag(ASN1_NULL);
  if(length != 0) return ASN1_BAD_LENGTH;
  cleanup();
}

asn1_error_code asn1_decode_printablestring(buf, retlen, val)
     asn1buf * buf;
     int * retlen;
     char ** val;
{
  setup();
  tag(ASN1_PRINTABLESTRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_ia5string(buf, retlen, val)
     asn1buf * buf;
     int * retlen;
     char ** val;
{
  setup();
  tag(ASN1_IA5STRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_generaltime(buf, val)
     asn1buf * buf;
     time_t * val;
{
  setup();
  char *s;
  struct tm ts;
  time_t t;

  tag(ASN1_GENERALTIME);

  if(length != 15) return ASN1_BAD_LENGTH;
  retval = asn1buf_remove_charstring(buf,15,&s);
  /* Time encoding: YYYYMMDDhhmmssZ */
  if(s[14] != 'Z') {
      free(s);
      return ASN1_BAD_FORMAT;
  }
#define c2i(c) ((c)-'0')
  ts.tm_year = 1000*c2i(s[0]) + 100*c2i(s[1]) + 10*c2i(s[2]) + c2i(s[3])
    - 1900;
  ts.tm_mon = 10*c2i(s[4]) + c2i(s[5]) - 1;
  ts.tm_mday = 10*c2i(s[6]) + c2i(s[7]);
  ts.tm_hour = 10*c2i(s[8]) + c2i(s[9]);
  ts.tm_min = 10*c2i(s[10]) + c2i(s[11]);
  ts.tm_sec = 10*c2i(s[12]) + c2i(s[13]);
  ts.tm_isdst = -1;
  t = gmt_mktime(&ts);
  free(s);

  if(t == -1) return ASN1_BAD_TIMEFORMAT;

  *val = t;
  cleanup();
}
