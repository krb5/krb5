/* ASN.1 primitive encoders */

#include "asn1_encode.h"
#include "asn1_make.h"

asn1_error_code asn1_encode_integer(DECLARG(asn1buf *, buf),
				    DECLARG(const long , val),
				    DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const long , val)
     OLDDECLARG(int *, retlen)
{
  asn1_error_code retval;
  int length = 0, partlen;
  long valcopy;
  int digit;
  
  valcopy = val;
  do {
    digit = valcopy&0xFF;
    retval = asn1buf_insert_octet(buf,digit);
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

asn1_error_code asn1_encode_unsigned_integer(DECLARG(asn1buf *, buf),
					     DECLARG(const unsigned long , val),
					     DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const unsigned long , val)
     OLDDECLARG(int *, retlen)
{
  asn1_error_code retval;
  int length = 0, partlen;
  unsigned long valcopy;
  int digit;
  
  valcopy = val;
  do {
    digit = valcopy&0xFF;
    retval = asn1buf_insert_octet(buf,digit);
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

asn1_error_code asn1_encode_octetstring(DECLARG(asn1buf *, buf),
					DECLARG(const int , len),
					DECLARG(const asn1_octet *, val),
					DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , len)
     OLDDECLARG(const asn1_octet *, val)
     OLDDECLARG(int *, retlen)
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

asn1_error_code asn1_encode_charstring(DECLARG(asn1buf *, buf),
				       DECLARG(const int , len),
				       DECLARG(const char *, val),
				       DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , len)
     OLDDECLARG(const char *, val)
     OLDDECLARG(int *, retlen)
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

asn1_encode_null(DECLARG(asn1buf *, buf),
		 DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(int *, retlen)
{
  asn1_error_code retval;
  
  retval = asn1buf_insert_octet(buf,0x00);
  if(retval) return retval;
  retval = asn1buf_insert_octet(buf,0x05);
  if(retval) return retval;

  *retlen = 2;
  return 0;
}

asn1_error_code asn1_encode_printablestring(DECLARG(asn1buf *, buf),
					    DECLARG(const int , len),
					    DECLARG(const char *, val),
					    DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , len)
     OLDDECLARG(const char *, val)
     OLDDECLARG(int *, retlen)
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

asn1_error_code asn1_encode_ia5string(DECLARG(asn1buf *, buf),
				      DECLARG(const int , len),
				      DECLARG(const char *, val),
				      DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , len)
     OLDDECLARG(const char *, val)
     OLDDECLARG(int *, retlen)
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

asn1_error_code asn1_encode_generaltime(DECLARG(asn1buf *, buf),
					DECLARG(const time_t , val),
					DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const time_t , val)
     OLDDECLARG(int *, retlen)
{
  asn1_error_code retval;
  struct tm *time = gmtime(&val);
  char s[16];
  int length, sum=0;

  /* Time encoding: YYYYMMDDhhmmssZ */
  if(!strftime(s,16,"%Y%m%d%H%M%SZ",time)) return ASN1_BAD_TIMEFORMAT;
  retval = asn1buf_insert_charstring(buf,15,s);
  if(retval) return retval;
  sum = 15;

  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_GENERALTIME,sum,&length);
  if(retval) return retval;
  sum += length;

  *retlen = sum;
  return 0;
}

asn1_error_code asn1_encode_generalstring(DECLARG(asn1buf *, buf),
					  DECLARG(const int , len),
					  DECLARG(const char *, val),
					  DECLARG(int *, retlen))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , len)
     OLDDECLARG(const char *, val)
     OLDDECLARG(int *, retlen)
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
