/*
 * src/lib/krb5/asn.1/asn1_encode.c
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

/* ASN.1 primitive encoders */

#include "asn1_encode.h"
#include "asn1_make.h"

asn1_error_code asn1_encode_integer(buf, val, retlen)
     asn1buf * buf;
     const long val;
     int * retlen;
{
  asn1_error_code retval;
  int length = 0, partlen;
  long valcopy;
  int digit;
  
  valcopy = val;
  do {
    digit = (int) (valcopy&0xFF);
    retval = asn1buf_insert_octet(buf,(asn1_octet) digit);
    if(retval) return retval;
    length++;
    valcopy = valcopy >> 8;
  } while (valcopy != 0 && valcopy != ~0);

  if((val > 0) && ((digit&0x80) == 0x80)) { /* make sure the high bit is */
    retval = asn1buf_insert_octet(buf,0); /* of the proper signed-ness */
    if(retval) return retval;
    length++;
  }else if((val < 0) && ((digit&0x80) != 0x80)){
    retval = asn1buf_insert_octet(buf,0xFF);
    if(retval) return retval;
    length++;
  }

  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_INTEGER,length, &partlen); 
  if(retval) return retval;
  length += partlen;

  *retlen = length;
  return 0;
}

asn1_error_code asn1_encode_unsigned_integer(buf, val, retlen)
     asn1buf * buf;
     const unsigned long val;
     int * retlen;
{
  asn1_error_code retval;
  int length = 0, partlen;
  unsigned long valcopy;
  int digit;
  
  valcopy = val;
  do {
    digit = (int) (valcopy&0xFF);
    retval = asn1buf_insert_octet(buf,(asn1_octet) digit);
    if(retval) return retval;
    length++;
    valcopy = valcopy >> 8;
  } while (valcopy != 0 && valcopy != ~0);

  if(digit&0x80) {		          /* make sure the high bit is */
    retval = asn1buf_insert_octet(buf,0); /* of the proper signed-ness */
    if(retval) return retval;
    length++;
  }

  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_INTEGER,length, &partlen); 
  if(retval) return retval;
  length += partlen;

  *retlen = length;
  return 0;
}

asn1_error_code asn1_encode_octetstring(buf, len, val, retlen)
     asn1buf * buf;
     const int len;
     const asn1_octet * val;
     int * retlen;
{
  asn1_error_code retval;
  int length;

  retval = asn1buf_insert_octetstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_OCTETSTRING,len,&length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}

asn1_error_code asn1_encode_charstring(buf, len, val, retlen)
     asn1buf * buf;
     const int len;
     const char * val;
     int * retlen;
{
  asn1_error_code retval;
  int length;

  retval = asn1buf_insert_charstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_OCTETSTRING,len,&length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}

asn1_error_code asn1_encode_null(buf, retlen)
     asn1buf * buf;
     int * retlen;
{
  asn1_error_code retval;
  
  retval = asn1buf_insert_octet(buf,0x00);
  if(retval) return retval;
  retval = asn1buf_insert_octet(buf,0x05);
  if(retval) return retval;

  *retlen = 2;
  return 0;
}

asn1_error_code asn1_encode_printablestring(buf, len, val, retlen)
     asn1buf * buf;
     const int len;
     const char * val;
     int * retlen;
{
  asn1_error_code retval;
  int length;

  retval = asn1buf_insert_charstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_PRINTABLESTRING,len,			 &length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}

asn1_error_code asn1_encode_ia5string(buf, len, val, retlen)
     asn1buf * buf;
     const int len;
     const char * val;
     int * retlen;
{
  asn1_error_code retval;
  int length;

  retval = asn1buf_insert_charstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_IA5STRING,len,			 &length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}

#ifdef macintosh
#define EPOCH ((70 * 365 * 24 * 60 * 60) + (17 *  24 * 60 * 60) + (getTimeZoneOffset() * 60 * 60))
#else
#define EPOCH (0)
#endif

asn1_error_code asn1_encode_generaltime(buf, val, retlen)
     asn1buf * buf;
     const time_t val;
     int * retlen;
{
  asn1_error_code retval;
  struct tm *gtime;
  char s[16];
  int length, sum=0;
  time_t gmt_time;

  gmt_time = val + EPOCH;
  gtime = gmtime(&gmt_time);

  /*
   * Time encoding: YYYYMMDDhhmmssZ
   *
   * Sanity check this just to be paranoid, as gmtime can return NULL,
   * and some bogus implementations might overrun on the sprintf.
   */
  if (gtime == NULL ||
      gtime->tm_year > 8099 || gtime->tm_mon > 11 ||
      gtime->tm_mday > 31 || gtime->tm_hour > 23 ||
      gtime->tm_min > 59 || gtime->tm_sec > 59)
    return ASN1_BAD_GMTIME;
  sprintf(s, "%04d%02d%02d%02d%02d%02dZ",
	  1900+gtime->tm_year, gtime->tm_mon+1, gtime->tm_mday,
	  gtime->tm_hour, gtime->tm_min, gtime->tm_sec);

  retval = asn1buf_insert_charstring(buf,15,s);
  if(retval) return retval;
  sum = 15;

  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_GENERALTIME,sum,&length);
  if(retval) return retval;
  sum += length;

  *retlen = sum;
  return 0;
}

asn1_error_code asn1_encode_generalstring(buf, len, val, retlen)
     asn1buf * buf;
     const int len;
     const char * val;
     int * retlen;
{
  asn1_error_code retval;
  int length;

  retval = asn1buf_insert_charstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_GENERALSTRING,len,
			 &length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}
