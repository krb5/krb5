/*
 * lib/krb5/ccache/stdio/scc_write.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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
 * This file contains the source code for krb5_scc_write_<type>.
 */



#include "scc.h"

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
krb5_scc_write(id, buf, len)
   krb5_ccache id;
   krb5_pointer buf;
   int len;
{
     int ret;

     errno = 0;
     ret = fwrite((char *) buf, 1, len, ((krb5_scc_data *)id->data)->file);
     if ((ret == 0) && errno) {
	  return krb5_scc_interpret (errno);
     } else if (ret != len)
	 return KRB5_CC_END;
     return KRB5_OK;
}

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 * 
 * Requires:
 * ((krb5_scc_data *) id->data)->file is open and at the right position.
 * 
 * Effects:
 * Stores an encoded version of the second argument in the
 * cache file.
 *
 * Errors:
 * system errors
 */

krb5_error_code
krb5_scc_store_principal(id, princ)
   krb5_ccache id;
   krb5_principal princ;
{
    krb5_scc_data *data = (krb5_scc_data *)id->data;
    krb5_error_code ret;
    krb5_int32 i, length, tmp, type;

    type = krb5_princ_type(princ);
    tmp = length = krb5_princ_size(princ);

    if (data->version == KRB5_SCC_FVNO_1) {
	/*
	 * DCE-compatible format means that the length count
	 * includes the realm.  (It also doesn't include the
	 * principal type information.)
	 */
	tmp++;
    } else {
        ret = krb5_scc_store_int32(id, &type);
        CHECK(ret);
    }
    
    ret = krb5_scc_store_int32(id, &tmp);
    CHECK(ret);

    ret = krb5_scc_store_data(id, krb5_princ_realm(princ));
    CHECK(ret);

    for (i=0; i < length; i++) {
	ret = krb5_scc_store_data(id, krb5_princ_component(princ, i));
	CHECK(ret);
    }

    return KRB5_OK;
}

krb5_error_code
krb5_scc_store_addrs(id, addrs)
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

     ret = krb5_scc_store_int32(id, &length);
     CHECK(ret);
     for (i=0; i < length; i++) {
	  ret = krb5_scc_store_addr(id, addrs[i]);
	  CHECK(ret);
     }

     return KRB5_OK;
}

krb5_error_code
krb5_scc_store_keyblock(id, keyblock)
   krb5_ccache id;
   krb5_keyblock *keyblock;
{
     krb5_error_code ret;

     ret = krb5_scc_store_keytype(id, &keyblock->keytype);
     CHECK(ret);
     ret = krb5_scc_store_int(id, &keyblock->length);
     CHECK(ret);
     errno = 0;
     ret = fwrite((char *)keyblock->contents, 1,
		  (keyblock->length)*sizeof(krb5_octet),
		  ((krb5_scc_data *) id->data)->file);
     if ((ret == 0) && errno)
	  return krb5_scc_interpret(errno);
     if (ret != (keyblock->length)*sizeof(krb5_octet))
	 return KRB5_CC_END;
     
     return KRB5_OK;
}

krb5_error_code
krb5_scc_store_addr(id, addr)
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code ret;

     ret = krb5_scc_store_ui_2(id, &addr->addrtype);
     CHECK(ret);
     ret = krb5_scc_store_int(id, &addr->length);
     CHECK(ret);
     errno = 0;
     ret = fwrite((char *)addr->contents, 1,
		  (addr->length)*sizeof(krb5_octet),
		  ((krb5_scc_data *) id->data)->file);
     if ((ret == 0) && errno)
	  return krb5_scc_interpret(errno);
     if (ret != (addr->length)*sizeof(krb5_octet))
	 return KRB5_CC_END;
     return KRB5_OK;
}


krb5_error_code
krb5_scc_store_data(id, data)
   krb5_ccache id;
   krb5_data *data;
{
     krb5_error_code ret;

     ret = krb5_scc_store_int32(id, &data->length);
     CHECK(ret);
     errno = 0;
     ret = fwrite(data->data, 1, data->length,
		  ((krb5_scc_data *) id->data)->file);
     if ((ret == 0) && errno)
	  return krb5_scc_interpret(errno);
     else if (ret != data->length)
	 return KRB5_CC_END;
     return KRB5_OK;
}

krb5_error_code
krb5_scc_store_int32(id, i)
   krb5_ccache id;
   krb5_int32 *i;
{
     return krb5_scc_write(id, (char *) i, sizeof(krb5_int32));
}

krb5_error_code
krb5_scc_store_ui_2(id, i)
   krb5_ccache id;
   krb5_ui_2 *i;
{
     return krb5_scc_write(id, (char *) i, sizeof(krb5_ui_2));
}
   
krb5_error_code
krb5_scc_store_keytype(id, k)
   krb5_ccache id;
   krb5_keytype *k;
{
     return krb5_scc_write(id, (char *) k, sizeof(krb5_keytype));
}
   
krb5_error_code
krb5_scc_store_int(id, i)
   krb5_ccache id;
   int *i;
{
     return krb5_scc_write(id, (char *) i, sizeof(int));
}
   
krb5_error_code
krb5_scc_store_bool(id, b)
   krb5_ccache id;
   krb5_boolean *b;
{
     return krb5_scc_write(id, (char *) b, sizeof(krb5_boolean));
}
   
krb5_error_code
krb5_scc_store_times(id, t)
   krb5_ccache id;
   krb5_ticket_times *t;
{
     return krb5_scc_write(id, (char *) t, sizeof(krb5_ticket_times));
}
   
krb5_error_code
krb5_scc_store_flags(id, f)
   krb5_ccache id;
   krb5_flags *f;
{
     return krb5_scc_write(id, (char *) f, sizeof(krb5_flags));
}

krb5_error_code
krb5_scc_store_authdata(id, a)
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

    ret = krb5_scc_store_int32(id, &length);
    CHECK(ret);
    for (i=0; i<length; i++) {
        ret = krb5_scc_store_authdatum (id, a[i]);
        CHECK(ret);
    }
    return KRB5_OK;
}

krb5_error_code
krb5_scc_store_authdatum (id, a)
    krb5_ccache id;
    krb5_authdata *a;
{
    krb5_error_code ret;
    ret = krb5_scc_store_ui_2(id, &a->ad_type);
    CHECK(ret);
    ret = krb5_scc_store_int32(id, &a->length);
    CHECK(ret);
    return krb5_scc_write(id, (krb5_pointer) a->contents, a->length);
}
