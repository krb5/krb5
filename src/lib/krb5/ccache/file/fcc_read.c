/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * 
 *
 * This file contains the source code for reading variables from a
 * credentials cache.  These are not library-exported functions.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_read_c[] =
"$Id$";
#endif /* !lint && !SABER */

#include "fcc.h"

#define CHECK(ret) if (ret != KRB5_OK) goto errout;
     
/*
 * Effects:
 * Reads len bytes from the cache id, storing them in buf.
 *
 * Errors:
 * KRB5_CC_END - there were not len bytes available
 * system errors (read)
 */
krb5_error_code
krb5_fcc_read(id, buf, len)
   krb5_ccache id;
   krb5_pointer buf;
   int len;
{
     int ret;

     ret = read(((krb5_fcc_data *) id->data)->fd, (char *) buf, len);
     if (ret == -1)
	  return krb5_fcc_interpret(errno);
     else if (ret != len)
	  return KRB5_CC_END;
     else
	  return KRB5_OK;
}

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 *
 * Requires:
 * id is open and set to read at the appropriate place in the file
 *
 * Effects:
 * Fills in the second argument with data of the appropriate type from
 * the file.  In some cases, the functions have to allocate space for
 * variable length fields; therefore, krb5_destroy_<type> must be
 * called for each filled in structure.
 *
 * Errors:
 * system errors (read errors)
 * KRB5_CC_NOMEM
 */

krb5_error_code
krb5_fcc_read_principal(id, princ)
   krb5_ccache id;
   krb5_principal *princ;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code kret;
    register krb5_principal tmpprinc;
    krb5_int32 length, type;
    int i;

    if (data->version == KRB5_FCC_FVNO_1) {
	type = KRB5_NT_UNKNOWN;
    } else {
        /* Read principal type */
        kret = krb5_fcc_read_int32(id, &type);
        if (kret != KRB5_OK)
	    return kret;
    }

    /* Read the number of components */
    kret = krb5_fcc_read_int32(id, &length);
    if (kret != KRB5_OK)
	return kret;

    tmpprinc = (krb5_principal) malloc(sizeof(krb5_principal_data));
    if (tmpprinc == NULL)
	return KRB5_CC_NOMEM;
    tmpprinc->data = malloc(length * sizeof(krb5_principal_data));
    if (tmpprinc->data == 0) {
	free((char *)tmpprinc);
	return KRB5_CC_NOMEM;
    }
    tmpprinc->length = length;
    tmpprinc->type = type;

    kret = krb5_fcc_read_data(id, krb5_princ_realm(tmpprinc));

    i = 0;
    CHECK(kret);

    for (i=0; i < length; i++) {
	kret = krb5_fcc_read_data(id, krb5_princ_component(tmpprinc, i));
	CHECK(kret);
    }
    *princ = tmpprinc;
    return KRB5_OK;

 errout:
    while(--i >= 0)
	free(krb5_princ_component(tmpprinc, i)->data);
    free((char *)tmpprinc->data);
    free((char *)tmpprinc);
    return KRB5_CC_NOMEM;
}

krb5_error_code
krb5_fcc_read_addrs(id, addrs)
   krb5_ccache id;
   krb5_address ***addrs;
{
     krb5_error_code kret;
     krb5_int32 length;
     int i;

     *addrs = 0;

     /* Read the number of components */
     kret = krb5_fcc_read_int32(id, &length);
     CHECK(kret);

     /* Make *addrs able to hold length pointers to krb5_address structs
      * Add one extra for a null-terminated list
      */
     *addrs = (krb5_address **) calloc(length+1, sizeof(krb5_address *));
     if (*addrs == NULL)
	  return KRB5_CC_NOMEM;

     for (i=0; i < length; i++) {
	  (*addrs)[i] = (krb5_address *) malloc(sizeof(krb5_address));
	  if ((*addrs)[i] == NULL) {
	      krb5_free_addresses(*addrs);
	      return KRB5_CC_NOMEM;
	  }	  
	  kret = krb5_fcc_read_addr(id, (*addrs)[i]);
	  CHECK(kret);
     }

     return KRB5_OK;
 errout:
     if (*addrs)
	 krb5_free_addresses(*addrs);
     return kret;
}

krb5_error_code
krb5_fcc_read_keyblock(id, keyblock)
   krb5_ccache id;
   krb5_keyblock *keyblock;
{
     krb5_error_code kret;
     int ret;

     keyblock->contents = 0;

     kret = krb5_fcc_read_keytype(id, &keyblock->keytype);
     CHECK(kret);
     kret = krb5_fcc_read_int(id, &keyblock->length);
     CHECK(kret);
     keyblock->contents = (unsigned char *) malloc(keyblock->length*
						   sizeof(krb5_octet));
     if (keyblock->contents == NULL)
	  return KRB5_CC_NOMEM;
     
     ret = read(((krb5_fcc_data *) id->data)->fd, (char *)keyblock->contents,
		(keyblock->length)*sizeof(krb5_octet));

     if (ret < 0) {
	 xfree(keyblock->contents);
	 return krb5_fcc_interpret(errno);
     }
     if (ret != (keyblock->length)*sizeof(krb5_octet)) {
	 xfree(keyblock->contents);
	 return KRB5_CC_END;
     }

     return KRB5_OK;
 errout:
     if (keyblock->contents)
	 xfree(keyblock->contents);
     return kret;
}

krb5_error_code
krb5_fcc_read_data(id, data)
   krb5_ccache id;
   krb5_data *data;
{
     krb5_error_code kret;
     int ret;

     data->data = 0;

     kret = krb5_fcc_read_int32(id, &data->length);
     CHECK(kret);

     if (data->length == 0) {
	data->data = 0;
	return KRB5_OK;
     }

     data->data = (char *) malloc(data->length+1);
     if (data->data == NULL)
	  return KRB5_CC_NOMEM;

     ret = read(((krb5_fcc_data *) id->data)->fd, (char *)data->data,
		data->length);
     if (ret == -1) {
	 xfree(data->data);
	 return krb5_fcc_interpret(errno);
     }
     if (ret != data->length) {
	 xfree(data->data);
	 return KRB5_CC_END;
     }
     data->data[data->length] = 0; /* Null terminate, just in case.... */
     return KRB5_OK;
}

krb5_error_code
krb5_fcc_read_addr(id, addr)
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code kret;
     int ret;

     addr->contents = 0;

     kret = krb5_fcc_read_ui_2(id, &addr->addrtype);
     CHECK(kret);

     kret = krb5_fcc_read_int(id, &addr->length);
     CHECK(kret);

     addr->contents = (krb5_octet *) malloc(addr->length);
     if (addr->contents == NULL)
	  return KRB5_CC_NOMEM;

     ret = read(((krb5_fcc_data *) id->data)->fd, (char *)addr->contents,
		(addr->length)*sizeof(krb5_octet));
     if (ret == -1) {
	  xfree(addr->contents);
	  return krb5_fcc_interpret(errno);
     }
     if (ret != (addr->length)*sizeof(krb5_octet)) {
	  xfree(addr->contents);
	  return KRB5_CC_END;
     }
     return KRB5_OK;
 errout:
     if (addr->contents)
	 xfree(addr->contents);
     return kret;
}

krb5_error_code
krb5_fcc_read_int32(id, i)
   krb5_ccache id;
   krb5_int32 *i;
{
     return krb5_fcc_read(id, (krb5_pointer) i, sizeof(krb5_int32));
}

krb5_error_code
krb5_fcc_read_ui_2(id, i)
   krb5_ccache id;
   krb5_ui_2 *i;
{
     return krb5_fcc_read(id, (krb5_pointer) i, sizeof(krb5_ui_2));
}

krb5_error_code
krb5_fcc_read_keytype(id, k)
   krb5_ccache id;
   krb5_keytype *k;
{
     return krb5_fcc_read(id, (krb5_pointer) k, sizeof(krb5_keytype));
}

krb5_error_code
krb5_fcc_read_int(id, i)
   krb5_ccache id;
   int *i;
{
     return krb5_fcc_read(id, (krb5_pointer) i, sizeof(int));
}

krb5_error_code
krb5_fcc_read_bool(id, b)
   krb5_ccache id;
   krb5_boolean *b;
{
     return krb5_fcc_read(id, (krb5_pointer) b, sizeof(krb5_boolean));
}

krb5_error_code
krb5_fcc_read_times(id, t)
   krb5_ccache id;
   krb5_ticket_times *t;
{
     return krb5_fcc_read(id, (krb5_pointer) t, sizeof(krb5_ticket_times));
}

krb5_error_code
krb5_fcc_read_flags(id, f)
   krb5_ccache id;
   krb5_flags *f;
{
     return krb5_fcc_read(id, (krb5_pointer) f, sizeof(krb5_flags));
}

krb5_error_code
krb5_fcc_read_authdata(id, a)
    krb5_ccache id;
    krb5_authdata ***a;
{
     krb5_error_code kret;
     krb5_int32 length;
     int i;

     *a = 0;

     /* Read the number of components */
     kret = krb5_fcc_read_int32(id, &length);
     CHECK(kret);

     if (length == 0)
	 return KRB5_OK;

     /* Make *a able to hold length pointers to krb5_authdata structs
      * Add one extra for a null-terminated list
      */
     *a = (krb5_authdata **) calloc(length+1, sizeof(krb5_authdata *));
     if (*a == NULL)
	  return KRB5_CC_NOMEM;

     for (i=0; i < length; i++) {
	  (*a)[i] = (krb5_authdata *) malloc(sizeof(krb5_authdata));
	  if ((*a)[i] == NULL) {
	      krb5_free_authdata(*a);
	      return KRB5_CC_NOMEM;
	  }	  
	  kret = krb5_fcc_read_authdatum(id, (*a)[i]);
	  CHECK(kret);
     }

     return KRB5_OK;
 errout:
     if (*a)
	 krb5_free_authdata(*a);
     return kret;
}

krb5_error_code
krb5_fcc_read_authdatum(id, a)
    krb5_ccache id;
    krb5_authdata *a;
{
    krb5_error_code kret;
    int ret;
    
    a->contents = NULL;

    kret = krb5_fcc_read_ui_2(id, &a->ad_type);
    CHECK(kret);
    kret = krb5_fcc_read_int(id, &a->length);
    CHECK(kret);
    
    a->contents = (krb5_octet *) malloc(a->length);
    if (a->contents == NULL)
	return KRB5_CC_NOMEM;
    ret = read(((krb5_fcc_data *) id->data)->fd, (char *)a->contents,
		(a->length)*sizeof(krb5_octet));
     if (ret == -1) {
	  xfree(a->contents);
	  return krb5_fcc_interpret(errno);
     }
     if (ret != (a->length)*sizeof(krb5_octet)) {
	  xfree(a->contents);
	  return KRB5_CC_END;
     }
     return KRB5_OK;
 errout:
     if (a->contents)
	 xfree(a->contents);
     return kret;
    
}
