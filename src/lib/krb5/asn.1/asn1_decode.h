#ifndef __ASN1_DECODE_H__
#define __ASN1_DECODE_H__

#include <krb5/krb5.h>
#include "krbasn1.h"
#include "asn1buf.h"

/*
   Overview

     These procedures take an asn1buf whose current position points
     to the beginning of an ASN.1 primitive (<id><length><contents>).
     The primitive is removed from the buffer and decoded.

   Operations

    asn1_decode_integer
    asn1_decode_unsigned_integer
    asn1_decode_octetstring
    asn1_decode_charstring
    asn1_decode_generalstring
    asn1_decode_null
    asn1_decode_printablestring
    asn1_decode_ia5string
    asn1_decode_generaltime
*/

/* asn1_error_code asn1_decode_type(asn1buf *buf, ctype *val); */
/* requires  *buf is allocated
   modifies  *buf, *len
   effects   Decodes the octet string in *buf into *val.
             Returns ENOMEM if memory is exhausted.
	     Returns asn1 errors. */

asn1_error_code asn1_decode_integer
	PROTOTYPE((asn1buf *buf, long *val));
asn1_error_code asn1_decode_unsigned_integer
	PROTOTYPE((asn1buf *buf, unsigned long *val));
asn1_error_code asn1_decode_null
	PROTOTYPE((asn1buf *buf));

asn1_error_code asn1_decode_octetstring
	PROTOTYPE((asn1buf *buf, int *retlen, asn1_octet **val));
asn1_error_code asn1_decode_generalstring
	PROTOTYPE((asn1buf *buf, int *retlen, char **val));
asn1_error_code asn1_decode_charstring
	PROTOTYPE((asn1buf *buf, int *retlen, char **val));
/* Note: A charstring is a special hack to account for the fact that
         krb5 structures store some OCTET STRING values in krb5_octet
	 arrays and others in krb5_data structures 
	PROTOTYPE((which use char arrays).
	 From the ASN.1 point of view, the two string types are the same,
	 only the receptacles differ. */
asn1_error_code asn1_decode_printablestring
	PROTOTYPE((asn1buf *buf, int *retlen, char **val));
asn1_error_code asn1_decode_ia5string
	PROTOTYPE((asn1buf *buf, int *retlen, char **val));

asn1_error_code asn1_decode_generaltime
	PROTOTYPE((asn1buf *buf, time_t *val));

#endif
