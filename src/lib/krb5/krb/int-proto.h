/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Function prototypes for Kerberos V5 library internal functions.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_INT_FUNC_PROTO__
#define __KRB5_INT_FUNC_PROTO__
krb5_error_code krb5_tgtname
    PROTOTYPE((krb5_principal,
	       krb5_principal,
	       krb5_principal *));
krb5_error_code krb5_get_cred_via_tgt
    PROTOTYPE((const krb5_creds *,
	       const krb5_flags,
	       const krb5_enctype,
	       const krb5_cksumtype,
	       const krb5_address **,
	       krb5_creds * ));
krb5_error_code krb5_walk_realm_tree
    PROTOTYPE((krb5_principal,
	       krb5_principal,
	       krb5_principal **));
krb5_error_code krb5_free_realm_tree
    PROTOTYPE((krb5_principal *));

#endif /* __KRB5_INT_FUNC_PROTO__ */

