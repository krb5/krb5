/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_write_<type>.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_write_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

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
	  return errno;
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

krb5_error_code
krb5_fcc_store_principal(id, princ)
   krb5_ccache id;
   krb5_principal princ;
{
     krb5_error_code ret;
     krb5_principal temp;
     krb5_int32 i, length = 0;

     /* Count the number of components */
     temp = princ;
     while (*temp++)
	  length += 1;

     ret = krb5_fcc_store_int32(id, &length);
     CHECK(ret);
     for (i=0; i < length; i++) {
	  ret = krb5_fcc_store_data(id, princ[i]);
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
	  return errno;
     if (ret != (keyblock->length)*sizeof(krb5_octet))
	 return KRB5_EOF;
     
     return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_addr(id, addr)
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code ret;

     ret = krb5_fcc_store_int16(id, &addr->addrtype);
     CHECK(ret);
     ret = krb5_fcc_store_int(id, &addr->length);
     CHECK(ret);
     ret = write(((krb5_fcc_data *) id->data)->fd, (char *)addr->contents,
		 (addr->length)*sizeof(krb5_octet));
     if (ret < 0)
	  return errno;
     if (ret != (addr->length)*sizeof(krb5_octet))
	 return KRB5_EOF;
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
	  return errno;

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
krb5_fcc_store_int16(id, i)
   krb5_ccache id;
   krb5_int16 *i;
{
     return krb5_fcc_write(id, (char *) i, sizeof(krb5_int16));
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
