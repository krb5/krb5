#ifndef __UTILITY_H__
#define __UTILITY_H__

#include "krbasn1.h"
#include "asn1buf.h"
#include "k5-int.h"

asn1_error_code asn1_krb5_data_unparse
	(const krb5_data *code, char **s);
/* modifies  *s;
   effects   Instantiates *s with a string representation of the series
	      of hex octets in *code.  (e.g. "02 02 00 7F")  If code==NULL,
	      the string rep is "<NULL>".  If code is empty (it contains no
	      data or has length <= 0), the string rep is "<EMPTY>".
	     If *s is non-NULL, then its currently-allocated storage
	      will be freed prior to the instantiation.
	     Returns ENOMEM or the string rep cannot be created. */

krb5_error_code krb5_data_parse
	(krb5_data *d, const char *s);
/* effects  Parses character string *s into krb5_data *d. */

krb5_error_code krb5_data_hex_parse
	(krb5_data *d, const char *s);
/* requires  *s is the string representation of a sequence of
              hexadecimal octets.  (e.g. "02 01 00")
   effects  Parses *s into krb5_data *d. */

void asn1buf_print
	(const asn1buf *buf);

extern krb5int_access acc;
extern void init_access(const char *progname);

#endif
