#ifndef __ASN1_ENCODE_H__
#define __ASN1_ENCODE_H__

#include <krb5/krb5.h>
#include <time.h>
#include "krbasn1.h"
#include "asn1buf.h"

/*
   Overview

     Each of these procedures inserts the encoding of an ASN.1
     primitive in a coding buffer.

   Operations

     asn1_encode_integer
     asn1_encode_octetstring
     asn1_encode_null
     asn1_encode_printablestring
     asn1_encode_ia5string
     asn1_encode_generaltime
     asn1_encode_generalstring
*/

asn1_error_code asn1_encode_integer
	PROTOTYPE((asn1buf *buf, const long val, int *retlen));
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_unsigned_integer
	PROTOTYPE((asn1buf *buf, const unsigned long val, int *retlen));
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_octetstring
	PROTOTYPE((asn1buf *buf,
		   const int len, const asn1_octet *val,
		   int *retlen));
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_charstring
	PROTOTYPE((asn1buf *buf,
		   const int len, const char *val,
		   int *retlen));
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_null
	PROTOTYPE((asn1buf *buf, int *retlen));
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of NULL into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_printablestring
	PROTOTYPE((asn1buf *buf,
		   const int len, const char *val,
		   int *retlen));
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_ia5string
	PROTOTYPE((asn1buf *buf,
		   const int len, const char *val,
		   int *retlen));
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_generaltime
	PROTOTYPE((asn1buf *buf, const time_t val, int *retlen));
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer.
   Note: The encoding of GeneralizedTime is YYYYMMDDhhmmZ */

asn1_error_code asn1_encode_generalstring
	PROTOTYPE((asn1buf *buf,
		   const int len, const char *val,
		   int *retlen));
/* requires  *buf is allocated,  val has a length of len characters
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

#endif
