/* ASN.1 primitive decoders */
#include "asn1_decode.h"
#include "asn1_get.h"
#include <time.h>

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

asn1_error_code asn1_decode_integer(DECLARG(asn1buf *, buf),
				    DECLARG(long *, val))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(long *, val)
{
  setup();
  asn1_octet o;
  unsigned long n;

  tag(ASN1_INTEGER);

  for(n=0; length > 0; length--){
    retval = asn1buf_remove_octet(buf,&o);
    if(retval) return retval;
    n = (n<<8) + (unsigned int)o;
  }
  *val = n;
  cleanup();
}

asn1_error_code asn1_decode_unsigned_integer(DECLARG(asn1buf *, buf),
					     DECLARG(unsigned long *, val))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(unsigned long *, val)
{
  setup();
  asn1_octet o;
  unsigned long n;

  tag(ASN1_INTEGER);

  for(n=0; length > 0; length--){
    retval = asn1buf_remove_octet(buf,&o);
    if(retval) return retval;
    n = (n<<8) + (unsigned int)o;
  }
  *val = n;
  cleanup();
}

asn1_error_code asn1_decode_octetstring(DECLARG(asn1buf *, buf),
					DECLARG(int *, retlen),
					DECLARG(asn1_octet **, val))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(int *, retlen)
     OLDDECLARG(asn1_octet **, val)
{
  setup();
  tag(ASN1_OCTETSTRING);
  retval = asn1buf_remove_octetstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_charstring(DECLARG(asn1buf *, buf),
				       DECLARG(int *, retlen),
				       DECLARG(char **, val))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(int *, retlen)
     OLDDECLARG(char **, val)
{
  setup();
  tag(ASN1_OCTETSTRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}


asn1_error_code asn1_decode_generalstring(DECLARG(asn1buf *, buf),
					  DECLARG(int *, retlen),
					  DECLARG(char **, val))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(int *, retlen)
     OLDDECLARG(char **, val)
{
  setup();
  tag(ASN1_GENERALSTRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}


asn1_error_code asn1_decode_null(DECLARG(asn1buf *, buf))
     OLDDECLARG(asn1buf *, buf)
{
  setup();
  tag(ASN1_NULL);
  if(length != 0) return ASN1_BAD_LENGTH;
  cleanup();
}

asn1_error_code asn1_decode_printablestring(DECLARG(asn1buf *, buf),
					    DECLARG(int *, retlen),
					    DECLARG(char **, val))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(int *, retlen)
     OLDDECLARG(char **, val)
{
  setup();
  tag(ASN1_PRINTABLESTRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_ia5string(DECLARG(asn1buf *, buf),
				      DECLARG(int *, retlen),
				      DECLARG(char **, val))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(int *, retlen)
     OLDDECLARG(char **, val)
{
  setup();
  tag(ASN1_IA5STRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_generaltime(DECLARG(asn1buf *, buf),
					DECLARG(time_t *, val))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(time_t *, val)
{
  setup();
  char *s;
  struct tm ts;
  time_t t;

  tag(ASN1_GENERALTIME);

  if(length != 15) return ASN1_BAD_LENGTH;
  retval = asn1buf_remove_charstring(buf,15,&s);
  /* Time encoding: YYYYMMDDhhmmssZ */
  if(s[14] != 'Z') return ASN1_BAD_FORMAT;
#define c2i(c) ((c)-'0')
  ts.tm_year = 1000*c2i(s[0]) + 100*c2i(s[1]) + 10*c2i(s[2]) + c2i(s[3])
    - 1900;
  ts.tm_mon = 10*c2i(s[4]) + c2i(s[5]) - 1;
  ts.tm_mday = 10*c2i(s[6]) + c2i(s[7]);
  ts.tm_hour = 10*c2i(s[8]) + c2i(s[9]);
  ts.tm_min = 10*c2i(s[10]) + c2i(s[11]);
  ts.tm_sec = 10*c2i(s[12]) + c2i(s[13]);
  ts.tm_isdst = -1;
  t = mktime(&ts);
  if(t == -1) return ASN1_BAD_TIMEFORMAT;
  t += ts.tm_gmtoff;		/* Convert back to UTC timezone */
                                /* !!!WARNING!!! tm_gmtoff is non-ANSI,
				   although it should exist in both
				   BSD and SYSV. */
  *val = t;
  cleanup();
}
