/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for reading variables from a
 * credentials cache.  These are not library-exported functions.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_read_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>
#include "fcc.h"

#define CHECK(ret) if (ret != KRB5_OK) goto errout;
     
/*
 * Effects:
 * Reads len bytes from the cache id, storing them in buf.
 *
 * Errors:
 * KRB5_EOF - there were not len bytes available
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
	  return errno;
     else if (ret != len)
	  return KRB5_EOF;
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
 * KRB5_NOMEM
 */

krb5_error_code
krb5_fcc_read_principal(id, princ)
   krb5_ccache id;
   krb5_principal *princ;
{
     krb5_error_code kret;
     krb5_int32 length;
     int i;

     *princ = 0;

     /* Read the number of components */
     kret = krb5_fcc_read_int32(id, &length);
     CHECK(kret);

     /*
      * The # of levels of indirection is confusing.  A krb5_principal
      * is an array of pointers to krb5_data.  princ is a pointer to
      * an array of pointers to krb5_data.  (*princ)[i] a pointer to
      * krb5_data.
      */

     /* Make *princ able to hold length pointers to krb5_data structs
      * Add one extra for a null-terminated list
      */
     *princ = (krb5_principal) calloc(length+1, sizeof(krb5_data *));
     if (*princ == NULL)
	  return KRB5_NOMEM;

     for (i=0; i < length; i++) {
	  (*princ)[i] = (krb5_data *) malloc(sizeof(krb5_data));
	  if ((*princ)[i] == NULL) {
	      krb5_free_principal(*princ);
	      return KRB5_NOMEM;
          }	  
	  kret = krb5_fcc_read_data(id, (*princ)[i]);
	  CHECK(kret);
     }

     return kret;
 errout:
     if (*princ)
	 krb5_free_principal(*princ);
     return kret;
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
	  return KRB5_NOMEM;

     for (i=0; i < length; i++) {
	  (*addrs)[i] = (krb5_address *) malloc(sizeof(krb5_address));
	  if ((*addrs)[i] == NULL) {
	      krb5_free_address(*addrs);
	      return KRB5_NOMEM;
	  }	  
	  kret = krb5_fcc_read_addr(id, (*addrs)[i]);
	  CHECK(kret);
     }

     return KRB5_OK;
 errout:
     if (*addrs)
	 krb5_free_address(*addrs);
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
	  return KRB5_NOMEM;
     
     ret = read(((krb5_fcc_data *) id->data)->fd, (char *)keyblock->contents,
		(keyblock->length)*sizeof(krb5_octet));

     if (ret < 0) {
	 xfree(keyblock->contents);
	 return errno;
     }
     if (ret != (keyblock->length)*sizeof(krb5_octet)) {
	 xfree(keyblock->contents);
	 return KRB5_EOF;
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

     data->data = (char *) malloc(data->length);
     if (data->data == NULL)
	  return KRB5_NOMEM;

     ret = read(((krb5_fcc_data *) id->data)->fd, (char *)data->data,
		data->length);
     if (ret == -1) {
	 xfree(data->data);
	 return errno;
     }
     if (ret != data->length) {
	 xfree(data->data);
	 return KRB5_EOF;
     }
     return KRB5_OK;
 errout:
     if (data->data)
	 xfree(data->data);
     return kret;
}

krb5_error_code
krb5_fcc_read_addr(id, addr)
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code kret;
     int ret;

     addr->contents = 0;

     kret = krb5_fcc_read_int16(id, &addr->addrtype);
     CHECK(kret);

     kret = krb5_fcc_read_int(id, &addr->length);
     CHECK(kret);

     addr->contents = (krb5_octet *) malloc(addr->length);
     if (addr->contents == NULL)
	  return KRB5_NOMEM;

     ret = read(((krb5_fcc_data *) id->data)->fd, (char *)addr->contents,
		(addr->length)*sizeof(krb5_octet));
     if (ret == -1) {
	  xfree(addr->contents);
	  return errno;
     }
     if (ret != (addr->length)*sizeof(krb5_octet)) {
	  xfree(addr->contents);
	  return KRB5_EOF;
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
krb5_fcc_read_int16(id, i)
   krb5_ccache id;
   krb5_int16 *i;
{
     return krb5_fcc_read(id, (krb5_pointer) i, sizeof(krb5_int16));
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
