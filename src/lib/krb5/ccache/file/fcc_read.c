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

#ifndef	lint
static char fcc_read_c[] = "$Id$";
#endif	lint

#include <krb5/copyright.h>

/* XXX Doesn't deal if < sizeof(o) bytes are written XXX */
#define krb5_fcc_read(i,b,l) (read(i->data->fd,b,l)==-1 ? errno : KRB5_OK)

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 *
 * Requires:
 * id->data->fd is open and at the right position in the file.
 *
 * Effects:
 * Allocates memory for and decodes the appropriate type from the
 * cache id.  The memory must be freed by the caller.
 *
 * Errors:
 * system errors
 * KRB5_NOMEM
 */

krb5_error
krb5_fcc_read_principal(krb5_ccache id, krb5_principal princ)
{
     krb5_error kret;
     krb5_int32 length;

     /* Read the number of components */
     krb5_fcc_read_int32(id, &length);

     /* Get memory for length components */
     princ = (krb5_principal) malloc(sizeof(krb5_data *)*length);
     if (princ == NULL)
	  return KRB5_NOMEM;

     /* Read length components */
     for (i=0; i < length; i++) {
	  kret = krb5_fcc_read_data(id, princ[i]);
     }

     return KRB5_OK;
}

krb5_error
krb5_fcc_read_keyblock(krb5_ccache id, krb5_keyblock *keyblock)
{
     krb5_error kret;
     int ret;

     keyblock = (krb5_keyblock *) malloc(sizeof(krb5_keyblock));
     if (keyblock == NULL)
	  return KRB5_NOMEM;
     
     kret = krb5_fcc_read_keytype(id, &keyblock->keytype);
     kret = krb5_fcc_read_int(id, &keyblock->length);
     ret = read(id->data->fd, keyblock->contents,
		(keyblock->length)*sizeof(krb5_octet));

     return KRB5_OK;
}

krb5_error
krb5_fcc_read_data(krb5_ccache id, krb5_data *data)
{
     krb5_error kret;
     int ret;

     data = (krb5_data *) malloc(sizeof(krb5_data));
     if (data == NULL)
	  return KRB5_NOMEM;

     kret = krb5_fcc_read_int32(id, data->length);

     data->data = (char *) malloc(data->length);
     if (data->data == NULL) {
	  free(data);
	  return KRB5_NOMEM;
     }

     ret = read(id->data->fd, data->data, data->length);
     if (ret == -1)
	  return errno;

     return KRB5_OK;
}

krb5_error
krb5_fcc_read_int32(krb5_ccache id, krb5_int32 *i)
{
     return krb5_fcc_read(id, i, sizeof(krb5_int32));
}

krb5_error
krb5_fcc_read_keytype(krb5_ccache id, krb5_keytype *k)
{
     return krb5_fcc_read(id, k, sizeof(krb5_keytype));
}

krb5_error
krb5_fcc_read_int(krb5_ccache id, int *i)
{
     return krb5_fcc_read(id, i, sizeof(int));
}

krb5_error
krb5_fcc_read_bool(krb5_ccache id, krb5_boolean *b)
{
     return krb5_fcc_read(id, b, sizeof(krb5_boolean));
}

krb5_error
krb5_fcc_read_times(krb5_ccache id, krb5_ticket_times *t)
{
     return krb5_fcc_read(id, t, sizeof(krb5_ticket_times));
}

