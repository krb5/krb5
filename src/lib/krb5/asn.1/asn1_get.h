#ifndef __ASN1_GET_H__
#define __ASN1_GET_H__

/* ASN.1 substructure decoding procedures */

#include <krb5/krb5.h>
#include "krbasn1.h"
#include "asn1buf.h"

asn1_error_code asn1_get_tag
	PROTOTYPE((asn1buf *buf,
		   asn1_class *class,
		   asn1_construction *construction,
		   asn1_tagnum *tagnum,
		   int *retlen));
/* requires  *buf is allocated
   effects   Decodes the tag in *buf.  If class != NULL, returns
              the class in *class.  Similarly, the construction,
	      tag number, and length are returned in *construction,
	      *tagnum, and *retlen, respectively.
	     If *buf is empty to begin with,
	      *tagnum is set to ASN1_TAGNUM_CEILING.
	     Returns ASN1_OVERRUN if *buf is exhausted during the parse. */

asn1_error_code asn1_get_sequence
	PROTOTYPE((asn1buf *buf, int *retlen));
/* requires  *buf is allocated
   effects   Decodes a tag from *buf and returns ASN1_BAD_ID if it
              doesn't have a sequence ID.  If retlen != NULL, the
	      associated length is returned in *retlen. */

/****************************************************************/
/* Private Procedures */

asn1_error_code asn1_get_id
	PROTOTYPE((asn1buf *buf,
		   asn1_class *class,
		   asn1_construction *construction,
		   asn1_tagnum *tagnum));
/* requires  *buf is allocated
   effects   Decodes the group of identifier octets at *buf's
              current position.  If class != NULL, returns the class
              in *class.  Similarly, the construction and tag number
              are returned in *construction and *tagnum, respectively.
	     Returns ASN1_OVERRUN if *buf is exhausted. */

asn1_error_code asn1_get_length
	PROTOTYPE((asn1buf *buf, int *retlen));
/* requires  *buf is allocated
   effects   Decodes the group of length octets at *buf's
              current position.  If retlen != NULL, the
	      length is returned in *retlen.
	     Returns ASN1_OVERRUN if *buf is exhausted. */

#endif
