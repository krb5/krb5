#ifndef __ASN1_MISC_H__
#define __ASN1_MISC_H__

#include <krb5/krb5.h>
#include "krbasn1.h"

asn1_error_code asn1_krb5_realm_copy
	PROTOTYPE((krb5_principal target, krb5_principal source));
/* requires  target, source, and source->realm are allocated
   effects   Copies source->realm into target->realm.
             Returns ENOMEM if memory is exhausted. */

#endif
