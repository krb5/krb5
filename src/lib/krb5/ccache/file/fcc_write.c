/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_fcc_write_<type>.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rcsid_fcc_write_c[] =
 "$Id$";
#endif /* !lint && !SABER */


#include "fcc.h"

#define CHECK(ret) if (ret != KRB5_OK) return ret;

/*
 * Requires:
 * id is open
 *
 * Effects:
 * Writes len bytes from buf into the file cred cache id.
 *
 * Errors:
 * system errors
 */
krb5_error_code
krb5_fcc_write(id, buf, len)
   krb5_ccache id;
   krb5_pointer buf;
   int len;
{
     int ret;

     ret = write(((krb5_fcc_data *)id->data)->fd, (char *) buf, len);
     if (ret < 0)
	  return krb5_fcc_interpret(errno);
     return KRB5_OK;
}

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 * 
 * Requires:
 * ((krb5_fcc_data *) id->data)->fd is open and at the right position.
 * 
 * Effects:
 * Stores an encoded version of the second argument in the
 * cache file.
 *
 * Errors:
 * system errors
 */

/* XXX TODO: write principal type to file XXX */

krb5_error_code
krb5_fcc_store_principal(id, princ)
   krb5_ccache id;
   krb5_principal princ;
{
    krb5_error_code ret;
    krb5_int32 i, length;

    length = krb5_princ_size(princ);

    ret = krb5_fcc_store_int32(id, &length);
    CHECK(ret);

    ret = krb5_fcc_store_data(id, krb5_princ_realm(princ));
    CHECK(ret);

    for (i=0; i < length; i++) {
	ret = krb5_fcc_store_data(id, krb5_princ_component(princ, i));
	CHECK(ret);
    }

    return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_addrs(id, addrs)
   krb5_ccache id;
   krb5_address ** addrs;
{
     krb5_error_code ret;
     krb5_address **temp;
     krb5_int32 i, length = 0;

     /* Count the number of components */
     temp = addrs;
     while (*temp++)
	  length += 1;

     ret = krb5_fcc_store_int32(id, &length);
     CHECK(ret);
     for (i=0; i < length; i++) {
	  ret = krb5_fcc_store_addr(id, addrs[i]);
	  CHECK(ret);
     }

     return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_keyblock(id, keyblock)
   krb5_ccache id;
   krb5_keyblock *keyblock;
{
     krb5_error_code ret;

     ret = krb5_fcc_store_keytype(id, &keyblock->keytype);
     CHECK(ret);
     ret = krb5_fcc_store_int(id, &keyblock->length);
     CHECK(ret);
     ret = write(((krb5_fcc_data *) id->data)->fd, (char *)keyblock->contents,
		 (keyblock->length)*sizeof(krb5_octet));
     if (ret < 0)
	  return krb5_fcc_interpret(errno);
     if (ret != (keyblock->length)*sizeof(krb5_octet))
	 return KRB5_CC_END;
     
     return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_addr(id, addr)
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code ret;

     ret = krb5_fcc_store_ui_2(id, &addr->addrtype);
     CHECK(ret);
     ret = krb5_fcc_store_int(id, &addr->length);
     CHECK(ret);
     ret = write(((krb5_fcc_data *) id->data)->fd, (char *)addr->contents,
		 (addr->length)*sizeof(krb5_octet));
     if (ret < 0)
	  return krb5_fcc_interpret(errno);
     if (ret != (addr->length)*sizeof(krb5_octet))
	 return KRB5_CC_END;
     return KRB5_OK;
}


krb5_error_code
krb5_fcc_store_data(id, data)
   krb5_ccache id;
   krb5_data *data;
{
     krb5_error_code ret;

     ret = krb5_fcc_store_int32(id, &data->length);
     CHECK(ret);
     ret = write(((krb5_fcc_data *) id->data)->fd, data->data, data->length);
     if (ret == -1)
	  return krb5_fcc_interpret(errno);

     return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_int32(id, i)
   krb5_ccache id;
   krb5_int32 *i;
{
     return krb5_fcc_write(id, (char *) i, sizeof(krb5_int32));
}

krb5_error_code
krb5_fcc_store_ui_2(id, i)
   krb5_ccache id;
   krb5_ui_2 *i;
{
     return krb5_fcc_write(id, (char *) i, sizeof(krb5_ui_2));
}
   
krb5_error_code
krb5_fcc_store_keytype(id, k)
   krb5_ccache id;
   krb5_keytype *k;
{
     return krb5_fcc_write(id, (char *) k, sizeof(krb5_keytype));
}
   
krb5_error_code
krb5_fcc_store_int(id, i)
   krb5_ccache id;
   int *i;
{
     return krb5_fcc_write(id, (char *) i, sizeof(int));
}
   
krb5_error_code
krb5_fcc_store_bool(id, b)
   krb5_ccache id;
   krb5_boolean *b;
{
     return krb5_fcc_write(id, (char *) b, sizeof(krb5_boolean));
}
   
krb5_error_code
krb5_fcc_store_times(id, t)
   krb5_ccache id;
   krb5_ticket_times *t;
{
     return krb5_fcc_write(id, (char *) t, sizeof(krb5_ticket_times));
}
   
krb5_error_code
krb5_fcc_store_flags(id, f)
   krb5_ccache id;
   krb5_flags *f;
{
     return krb5_fcc_write(id, (char *) f, sizeof(krb5_flags));
}

krb5_error_code
krb5_fcc_store_authdata(id, a)
    krb5_ccache id;
    krb5_authdata **a;
{
    krb5_error_code ret;
    krb5_authdata **temp;
    krb5_int32 i, length=0;

    if (a != NULL) {
	for (temp=a; *temp; temp++)
	    length++;
    }

    ret = krb5_fcc_store_int32(id, &length);
    CHECK(ret);
    for (i=0; i<length; i++) {
	ret = krb5_fcc_store_authdatum (id, a[i]);
	CHECK(ret);
    }
    return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_authdatum (id, a)
    krb5_ccache id;
    krb5_authdata *a;
{
    krb5_error_code ret;
    ret = krb5_fcc_store_ui_2(id, &a->ad_type);
    CHECK(ret);
    ret = krb5_fcc_store_int32(id, &a->length);
    CHECK(ret);
    return krb5_fcc_write(id, (krb5_pointer) a->contents, a->length);
}
