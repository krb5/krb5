#include "asn1_misc.h"

asn1_error_code asn1_krb5_realm_copy(DECLARG(krb5_principal, target),
				     DECLARG(krb5_principal, source))
     OLDDECLARG(krb5_principal, target)
     OLDDECLARG(krb5_principal, source)
{
  target->realm.length = source->realm.length;
  target->realm.data = (char*)calloc(target->realm.length,
					  sizeof(char)); /* copy realm */
  if(target->realm.data == NULL) return ENOMEM;
  memcpy(target->realm.data,source->realm.data, /* to client */
	 target->realm.length);
  return 0;
}
