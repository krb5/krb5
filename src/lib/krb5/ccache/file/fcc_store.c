/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_store.
 */

#ifndef	lint
static char fcc_store_c[] = "$Id$";
#endif	/* lint */

#include <krb5/copyright.h>

#include "fcc.h"

/* XXX Doesn't deal if < sizeof(o) bytes are written XXX */
#define krb5_fcc_write(i,b,l) (write(i->data->fd,b,l)==-1 ? errno : KRB5_OK)
#define krb5_fcc_store_int32(id,i) krb5_fcc_write(id, i, sizeof(krb5_int32))
#define krb5_fcc_store_keytype(id,k) krb5_fcc_write(id,k,sizeof(krb5_keytype))
#define krb5_fcc_store_int(id,i) krb5_fcc_write(id,i,sizeof(int))
#define krb5_fcc_store_bool(id,b) krb5_fcc_write(id,b,sizeof(krb5_boolean))
#define krb5_fcc_store_times(id,t) krb5_fcc_write(id,t,sizeof(krb5_ticket_times))

#define CHECK(ret) if (ret != KRB5_OK) return ret;

/*
 * Modifies:
 * the file cache
 *
 * Effects:
 * stores creds in the file cred cache
 *
 * Errors:
 * system errors
 * storage failure errors
 */
krb5_error
krb5_fcc_store(id, creds)
   krb5_ccache id;
   krb5_creds *creds;
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     krb5_error ret;

     /* Make sure we are writing to the end of the file */
#ifdef OPENCLOSE
     id->data->fd = open(id->data->filename, O_APPEND, 0);
     if (id->data->fd < 0)
	  return errno;
#else
     ret = lseek(id->data->fd, L_XTND, 0);
     if (ret < 0)
	  return errno;
#endif

     ret = krb5_fcc_store_principal(id, creds->client);
     TCHECK(ret);
     ret = krb5_fcc_store_principal(id, creds->server);
     TCHECK(ret);
     ret = krb5_fcc_store_keyblock(id, &creds->keyblock);
     TCHECK(ret);
     ret = krb5_fcc_store_times(id, &creds->times);
     TCHECK(ret);
     ret = krb5_fcc_store_bool(id, &creds->is_skey);
     TCHECK(ret);
     ret = krb5_fcc_store_data(id, &creds->ticket);
     TCHECK(ret);
     ret = krb5_fcc_store_data(id, &creds->second_ticket);
     TCHECK(ret);

lose:
          
#ifdef OPENCLOSE
     close(id->data->fd);
#endif

     return ret;
#undef TCHECK
}

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 * 
 * Requires:
 * id->data->fd is open and at the right position.
 * 
 * Effects:
 * Stores an encoded version of the second argument in the
 * cache file.
 *
 * Errors:
 * system errors
 */

static krb5_error
krb5_fcc_store_principal(id, princ)
   krb5_ccache id;
   krb5_principal princ;
{
     krb5_error ret;
     krb5_principal temp;
     krb5_int32 i, length = 0;

     /* Count the number of components */
     temp = princ;
     while (temp++)
	  length += 1;

     ret = krb5_fcc_store_int32(id, &length);
     CHECK(ret);
     for (i=0; i < length; i++) {
	  ret = krb5_store_data(id, princ[i]);
	  CHECK(ret);
     }

     return KRB5_OK;
}

static krb5_error
krb5_store_keyblock(id, keyblock)
   krb5_ccache id;
   krb5_keyblock *keyblock;
{
     krb5_error ret;

     ret = krb5_fcc_store_keytype(id, &keyblock->keytype);
     CHECK(ret);
     ret = krb5_fcc_store_int(id, &keyblock->length);
     CHECK(ret);
     ret = write(id->data->fd, keyblock->contents,
		 (keyblock->length)*sizeof(krb5_octet));
     CHECK(ret);
     
     return KRB5_OK;
}


static krb5_error
krb5_fcc_store_data(id, data)
   krb5_ccache id;
   krb5_data *data;
{
     krb5_error ret;

     ret = krb5_fcc_store_int32(id, data->length);
     CHECK(ret);
     ret = write(id->data->fd, data->data, data->length);
     if (ret == -1)
	  return errno;

     return KRB5_OK;
}

     
