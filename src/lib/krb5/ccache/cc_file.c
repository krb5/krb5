/*
 * lib/krb5/ccache/cc_file.c
 *
 * Copyright 1990,1991,1992,1993,1994,2000 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * implementation of file-based credentials cache
 */

/*
If OPENCLOSE is defined, ecah of the functions opens and closes the
file whenever it needs to access it.  Otherwise, the file is opened
once in initialize and closed once is close.

This library depends on UNIX-like file descriptors, and UNIX-like
behavior from the functions: open, close, read, write, lseek.

The quasi-BNF grammar for a credentials cache:

file ::= 
	principal list-of-credentials

credential ::=
	client (principal)
	server (principal)
	keyblock (keyblock)
	times (ticket_times)
	is_skey (boolean)
	ticket_flags (flags)
	ticket (data)
	second_ticket (data)

principal ::= 
	number of components (int32)
	component 1 (data)
	component 2 (data)
	...
	
data ::=
	length (int32)
	string of length bytes

etc.
 */
/* todo:
Make sure that each time a function returns KRB5_NOMEM, everything
allocated earlier in the function and stack tree is freed.

File locking

fcc_nseq.c and fcc_read don't check return values a lot.

 */
#include "k5-int.h"

#define NEED_SOCKETS    /* Only for ntohs, etc. */
#define NEED_LOWLEVEL_IO

#include <stdio.h>
#include <errno.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
          

#ifdef HAVE_NETINET_IN_H
#if !defined(_WINSOCKAPI_) && !defined(HAVE_MACSOCK_H)
#include <netinet/in.h>
#endif
#else
 #error find some way to use net-byte-order file version numbers.
#endif

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_close
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_destroy 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_end_seq_get 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_generate_new 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache *id ));

KRB5_DLLIMP char * KRB5_CALLCONV krb5_fcc_get_name 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_get_principal 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal *princ ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_initialize 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal princ ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_next_cred 
        KRB5_PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds ));

krb5_error_code krb5_fcc_read
        KRB5_PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_pointer buf,
		   int len));
krb5_error_code krb5_fcc_read_principal 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal *princ ));
krb5_error_code krb5_fcc_read_keyblock 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_fcc_read_data 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_fcc_read_int32 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 *i ));
krb5_error_code krb5_fcc_read_ui_2 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_ui_2 *i ));
krb5_error_code krb5_fcc_read_octet 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_octet *i ));
krb5_error_code krb5_fcc_read_times 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_ticket_times *t ));
krb5_error_code krb5_fcc_read_addrs 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache, krb5_address ***));
krb5_error_code krb5_fcc_read_addr 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache, krb5_address *));
krb5_error_code krb5_fcc_read_authdata 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata ***));
krb5_error_code krb5_fcc_read_authdatum 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata *));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_resolve 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache *id , const char *residual ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_retrieve 
        KRB5_PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_start_seq_get 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_store 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_creds *creds ));

krb5_error_code krb5_fcc_skip_header
        KRB5_PROTOTYPE((krb5_context, krb5_ccache));
krb5_error_code krb5_fcc_skip_principal 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_set_flags 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_flags flags ));

KRB5_DLLIMP extern krb5_cc_ops krb5_cc_file_ops;
krb5_error_code krb5_change_cache
   KRB5_PROTOTYPE((void));

krb5_error_code krb5_fcc_write 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_pointer buf , int len ));
krb5_error_code krb5_fcc_store_principal 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal princ ));
krb5_error_code krb5_fcc_store_keyblock 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_fcc_store_data 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_fcc_store_int32 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 i ));
krb5_error_code krb5_fcc_store_ui_2 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 i ));
krb5_error_code krb5_fcc_store_octet 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 i ));
krb5_error_code krb5_fcc_store_times 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_ticket_times *t ));
krb5_error_code krb5_fcc_store_addrs 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_address ** ));
krb5_error_code krb5_fcc_store_addr 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_address * ));
krb5_error_code krb5_fcc_store_authdata 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata **));
krb5_error_code krb5_fcc_store_authdatum 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata *));

krb5_error_code krb5_fcc_interpret 
        KRB5_PROTOTYPE((krb5_context, int ));

krb5_error_code krb5_fcc_close_file 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache));
krb5_error_code krb5_fcc_open_file 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache, int));


#define KRB5_OK 0

#define KRB5_FCC_MAXLEN 100

/*
 * FCC version 2 contains type information for principals.  FCC
 * version 1 does not.
 *  
 * FCC version 3 contains keyblock encryption type information, and is
 * architecture independent.  Previous versions are not.
 *
 * The code will accept version 1, 2, and 3 ccaches, and depending 
 * what KRB5_FCC_DEFAULT_FVNO is set to, it will create version 1, 2,
 * or 3 FCC caches.
 *
 * The default credentials cache should be type 3 for now (see
 * init_ctx.c).
 */

#define KRB5_FCC_FVNO_1 0x0501		/* krb5 v5, fcc v1 */
#define KRB5_FCC_FVNO_2 0x0502		/* krb5 v5, fcc v2 */
#define KRB5_FCC_FVNO_3 0x0503		/* krb5 v5, fcc v3 */
#define KRB5_FCC_FVNO_4 0x0504		/* krb5 v5, fcc v4 */

#define	FCC_OPEN_AND_ERASE	1
#define	FCC_OPEN_RDWR		2
#define	FCC_OPEN_RDONLY		3

/* Credential file header tags.
 * The header tags are constructed as:
 *	krb5_ui_2	tag
 *	krb5_ui_2	len
 *	krb5_octet	data[len]
 * This format allows for older versions of the fcc processing code to skip
 * past unrecognized tag formats.
 */
#define FCC_TAG_DELTATIME	1

#ifndef TKT_ROOT
#ifdef MSDOS_FILESYSTEM
#define TKT_ROOT "\\tkt"
#else
#define TKT_ROOT "/tmp/tkt"
#endif
#endif

/* macros to make checking flags easier */
#define OPENCLOSE(id) (((krb5_fcc_data *)id->data)->flags & KRB5_TC_OPENCLOSE)

typedef struct _krb5_fcc_data {
     char *filename;
     int fd;
     krb5_flags flags;
     int mode;				/* needed for locking code */
     int version;	      		/* version number of the file */
} krb5_fcc_data;

/* An off_t can be arbitrarily complex */
typedef struct _krb5_fcc_cursor {
     off_t pos;
} krb5_fcc_cursor;

#define MAYBE_OPEN(CONTEXT, ID, MODE) \
{									\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_open_ret = krb5_fcc_open_file (CONTEXT,ID,MODE);	\
	if (maybe_open_ret) return maybe_open_ret; } }

#define MAYBE_CLOSE(CONTEXT, ID, RET) \
{									\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_close_ret = krb5_fcc_close_file (CONTEXT,ID);	\
	if (!(RET)) RET = maybe_close_ret; } }

#define MAYBE_CLOSE_IGNORE(CONTEXT, ID) \
{									\
    if (OPENCLOSE (ID)) {						\
	(void) krb5_fcc_close_file (CONTEXT,ID); } }

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
krb5_fcc_read(context, id, buf, len)
   krb5_context context;
   krb5_ccache id;
   krb5_pointer buf;
   int len;
{
     int ret;

     ret = read(((krb5_fcc_data *) id->data)->fd, (char *) buf, len);
     if (ret == -1)
	  return krb5_fcc_interpret(context, errno);
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
krb5_fcc_read_principal(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal *princ;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code kret;
    register krb5_principal tmpprinc;
    krb5_int32 length, type, msize;
    int i;

    if (data->version == KRB5_FCC_FVNO_1) {
	type = KRB5_NT_UNKNOWN;
    } else {
        /* Read principal type */
        kret = krb5_fcc_read_int32(context, id, &type);
        if (kret != KRB5_OK)
	    return kret;
    }

    /* Read the number of components */
    kret = krb5_fcc_read_int32(context, id, &length);
    if (kret != KRB5_OK)
	return kret;

    /*
     * DCE includes the principal's realm in the count; the new format
     * does not.
     */
    if (data->version == KRB5_FCC_FVNO_1)
	length--;

    tmpprinc = (krb5_principal) malloc(sizeof(krb5_principal_data));
    if (tmpprinc == NULL)
	return KRB5_CC_NOMEM;
    if (length) {
            tmpprinc->data = 0;
            msize = length * sizeof(krb5_data);
            if ((msize & VALID_UINT_BITS) == msize)  /* Not overflow size_t */
        	    tmpprinc->data = (krb5_data *) malloc((size_t) msize);
	    if (tmpprinc->data == (krb5_data *) 0) {
		    free((char *)tmpprinc);
		    return KRB5_CC_NOMEM;
	    }
    } else
	    tmpprinc->data = 0;
    tmpprinc->magic = KV5M_PRINCIPAL;
    tmpprinc->length = length;
    tmpprinc->type = type;

    kret = krb5_fcc_read_data(context, id, krb5_princ_realm(context, tmpprinc));

    i = 0;
    CHECK(kret);

    for (i=0; i < length; i++) {
	kret = krb5_fcc_read_data(context, id, krb5_princ_component(context, tmpprinc, i));
	CHECK(kret);
    }
    *princ = tmpprinc;
    return KRB5_OK;

 errout:
    while(--i >= 0)
	free(krb5_princ_component(context, tmpprinc, i)->data);
    free((char *)tmpprinc->data);
    free((char *)tmpprinc);
    return kret;
}

krb5_error_code
krb5_fcc_read_addrs(context, id, addrs)
   krb5_context context;
   krb5_ccache id;
   krb5_address ***addrs;
{
     krb5_error_code kret;
     krb5_int32 length, msize;
     int i;

     *addrs = 0;

     /* Read the number of components */
     kret = krb5_fcc_read_int32(context, id, &length);
     CHECK(kret);

     /* Make *addrs able to hold length pointers to krb5_address structs
      * Add one extra for a null-terminated list
      */
     msize = length+1;
     if ((msize & VALID_UINT_BITS) != msize)    /* Overflow size_t??? */
	  return KRB5_CC_NOMEM;
     *addrs = (krb5_address **) calloc((size_t) msize, sizeof(krb5_address *));
     if (*addrs == NULL)
	  return KRB5_CC_NOMEM;

     for (i=0; i < length; i++) {
	  (*addrs)[i] = (krb5_address *) malloc(sizeof(krb5_address));
	  if ((*addrs)[i] == NULL) {
	      krb5_free_addresses(context, *addrs);
	      return KRB5_CC_NOMEM;
	  }	  
	  kret = krb5_fcc_read_addr(context, id, (*addrs)[i]);
	  CHECK(kret);
     }

     return KRB5_OK;
 errout:
     if (*addrs)
	 krb5_free_addresses(context, *addrs);
     return kret;
}

krb5_error_code
krb5_fcc_read_keyblock(context, id, keyblock)
   krb5_context context;
   krb5_ccache id;
   krb5_keyblock *keyblock;
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code kret;
     krb5_ui_2 ui2;
     krb5_int32 int32;

     keyblock->magic = KV5M_KEYBLOCK;
     keyblock->contents = 0;

     kret = krb5_fcc_read_ui_2(context, id, &ui2);
     keyblock->enctype = ui2;
     CHECK(kret);
     if (data->version == KRB5_FCC_FVNO_3) {
	     kret = krb5_fcc_read_ui_2(context, id, &ui2);
	     /* keyblock->enctype = ui2; */
	     CHECK(kret);
     }

     kret = krb5_fcc_read_int32(context, id, &int32);
     CHECK(kret);
#if defined(_MSDOS)
     int32 &= VALID_INT_BITS;    /* Gradient does not write  correctly */     
#else
     if ((int32 & VALID_INT_BITS) != int32)     /* Overflow size_t??? */
	  return KRB5_CC_NOMEM;
#endif
     keyblock->length = (int) int32;
     if ( keyblock->length == 0 )
	     return KRB5_OK;
     keyblock->contents = (unsigned char *) malloc(keyblock->length*
						   sizeof(krb5_octet));
     if (keyblock->contents == NULL)
	  return KRB5_CC_NOMEM;
     
     kret = krb5_fcc_read(context, id, keyblock->contents, keyblock->length);
     if (kret)
	 goto errout;

     return KRB5_OK;
 errout:
     if (keyblock->contents)
	 krb5_xfree(keyblock->contents);
     return kret;
}

krb5_error_code
krb5_fcc_read_data(context, id, data)
   krb5_context context;
   krb5_ccache id;
   krb5_data *data;
{
     krb5_error_code kret;
     krb5_int32 len;

     data->magic = KV5M_DATA;
     data->data = 0;

     kret = krb5_fcc_read_int32(context, id, &len);
     CHECK(kret);
#if defined(_MSDOS)
     len &= VALID_INT_BITS;
#else
     if ((len & VALID_INT_BITS) != len)
        return KRB5_CC_NOMEM;
#endif
     data->length = (int) len;

     if (data->length == 0) {
	data->data = 0;
	return KRB5_OK;
     }

     data->data = (char *) malloc(data->length+1);
     if (data->data == NULL)
	  return KRB5_CC_NOMEM;

     kret = krb5_fcc_read(context, id, data->data, data->length);
     CHECK(kret);
     
     data->data[data->length] = 0; /* Null terminate, just in case.... */
     return KRB5_OK;
 errout:
     if (data->data)
	 krb5_xfree(data->data);
     return kret;
}

krb5_error_code
krb5_fcc_read_addr(context, id, addr)
   krb5_context context;
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code kret;
     krb5_ui_2 ui2;
     krb5_int32 int32;

     addr->magic = KV5M_ADDRESS;
     addr->contents = 0;

     kret = krb5_fcc_read_ui_2(context, id, &ui2);
     CHECK(kret);
     addr->addrtype = ui2;
     
     kret = krb5_fcc_read_int32(context, id, &int32);
     CHECK(kret);
#if defined(_MSDOS)
     int32 &= VALID_INT_BITS;	/* Gradient DCE does this wrong */
#else
     if ((int32 & VALID_INT_BITS) != int32)     /* Overflow int??? */
	  return KRB5_CC_NOMEM;
#endif
     addr->length = (int) int32;

     if (addr->length == 0)
	     return KRB5_OK;

     addr->contents = (krb5_octet *) malloc(addr->length);
     if (addr->contents == NULL)
	  return KRB5_CC_NOMEM;

     kret = krb5_fcc_read(context, id, addr->contents, addr->length);
     CHECK(kret);

     return KRB5_OK;
 errout:
     if (addr->contents)
	 krb5_xfree(addr->contents);
     return kret;
}

krb5_error_code
krb5_fcc_read_int32(context, id, i)
   krb5_context context;
   krb5_ccache id;
   krb5_int32 *i;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code retval;
    unsigned char buf[4];
    krb5_int32 val;

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2)) 
	return krb5_fcc_read(context, id, (krb5_pointer) i, sizeof(krb5_int32));
    else {
	retval = krb5_fcc_read(context, id, buf, 4);
	if (retval)
	    return retval;
        val = buf[0];
        val = (val << 8) | buf[1];
        val = (val << 8) | buf[2];
        val = (val << 8) | buf[3];
        *i = val;
	return 0;
    }
}

krb5_error_code
krb5_fcc_read_ui_2(context, id, i)
   krb5_context context;
   krb5_ccache id;
   krb5_ui_2 *i;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code retval;
    unsigned char buf[2];
    
    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_read(context, id, (krb5_pointer) i, sizeof(krb5_ui_2));
    else {
	retval = krb5_fcc_read(context, id, buf, 2);
	if (retval)
	    return retval;
	*i = (buf[0] << 8) + buf[1];
	return 0;
    }
}    

krb5_error_code
krb5_fcc_read_octet(context, id, i)
   krb5_context context;
   krb5_ccache id;
   krb5_octet *i;
{
    return krb5_fcc_read(context, id, (krb5_pointer) i, 1);
}    


krb5_error_code
krb5_fcc_read_times(context, id, t)
   krb5_context context;
   krb5_ccache id;
   krb5_ticket_times *t;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code retval;
    krb5_int32 i;
    
    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_read(context, id, (krb5_pointer) t, sizeof(krb5_ticket_times));
    else {
	retval = krb5_fcc_read_int32(context, id, &i);
	CHECK(retval);
	t->authtime = i;
	
	retval = krb5_fcc_read_int32(context, id, &i);
	CHECK(retval);
	t->starttime = i;

	retval = krb5_fcc_read_int32(context, id, &i);
	CHECK(retval);
	t->endtime = i;

	retval = krb5_fcc_read_int32(context, id, &i);
	CHECK(retval);
	t->renew_till = i;
    }
    return 0;
errout:
    return retval;
}

krb5_error_code
krb5_fcc_read_authdata(context, id, a)
   krb5_context context;
    krb5_ccache id;
    krb5_authdata ***a;
{
     krb5_error_code kret;
     krb5_int32 length, msize;
     int i;

     *a = 0;

     /* Read the number of components */
     kret = krb5_fcc_read_int32(context, id, &length);
     CHECK(kret);

     if (length == 0)
	 return KRB5_OK;

     /* Make *a able to hold length pointers to krb5_authdata structs
      * Add one extra for a null-terminated list
      */
     msize = length+1;
     if ((msize & VALID_UINT_BITS) != msize)    /* Overflow size_t??? */
	  return KRB5_CC_NOMEM;
     *a = (krb5_authdata **) calloc((size_t) msize, sizeof(krb5_authdata *));
     if (*a == NULL)
	  return KRB5_CC_NOMEM;

     for (i=0; i < length; i++) {
	  (*a)[i] = (krb5_authdata *) malloc(sizeof(krb5_authdata));
	  if ((*a)[i] == NULL) {
	      krb5_free_authdata(context, *a);
	      return KRB5_CC_NOMEM;
	  }	  
	  kret = krb5_fcc_read_authdatum(context, id, (*a)[i]);
	  CHECK(kret);
     }

     return KRB5_OK;
 errout:
     if (*a)
	 krb5_free_authdata(context, *a);
     return kret;
}

krb5_error_code
krb5_fcc_read_authdatum(context, id, a)
   krb5_context context;
    krb5_ccache id;
    krb5_authdata *a;
{
    krb5_error_code kret;
    krb5_int32 int32;
    krb5_ui_2 ui2;
    
    a->magic = KV5M_AUTHDATA;
    a->contents = NULL;

    kret = krb5_fcc_read_ui_2(context, id, &ui2);
    CHECK(kret);
    a->ad_type = (krb5_authdatatype)ui2;
    kret = krb5_fcc_read_int32(context, id, &int32);
    CHECK(kret);
#ifdef _MSDOS
    int32 &= VALID_INT_BITS;
#else
    if ((int32 & VALID_INT_BITS) != int32)     /* Overflow int??? */
          return KRB5_CC_NOMEM;
#endif
    a->length = (int) int32;
    
    if (a->length == 0 )
	    return KRB5_OK;

    a->contents = (krb5_octet *) malloc(a->length);
    if (a->contents == NULL)
	return KRB5_CC_NOMEM;

    kret = krb5_fcc_read(context, id, a->contents, a->length);
    CHECK(kret);
    
     return KRB5_OK;
 errout:
     if (a->contents)
	 krb5_xfree(a->contents);
     return kret;
    
}
/* end of former file/fcc_read.c */
#undef CHECK

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
krb5_fcc_write(context, id, buf, len)
   krb5_context context;
   krb5_ccache id;
   krb5_pointer buf;
   int len;
{
     int ret;

     ret = write(((krb5_fcc_data *)id->data)->fd, (char *) buf, len);
     if (ret < 0)
	  return krb5_fcc_interpret(context, errno);
     if (ret != len)
	 return KRB5_CC_WRITE;
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
krb5_fcc_store_principal(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal princ;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code ret;
    krb5_int32 i, length, tmp, type;

    type = krb5_princ_type(context, princ);
    tmp = length = krb5_princ_size(context, princ);

    if (data->version == KRB5_FCC_FVNO_1) {
	/*
	 * DCE-compatible format means that the length count
	 * includes the realm.  (It also doesn't include the
	 * principal type information.)
	 */
	tmp++;
    } else {
	ret = krb5_fcc_store_int32(context, id, type);
	CHECK(ret);
    }
    
    ret = krb5_fcc_store_int32(context, id, tmp);
    CHECK(ret);

    ret = krb5_fcc_store_data(context, id, krb5_princ_realm(context, princ));
    CHECK(ret);

    for (i=0; i < length; i++) {
	ret = krb5_fcc_store_data(context, id, krb5_princ_component(context, princ, i));
	CHECK(ret);
    }

    return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_addrs(context, id, addrs)
   krb5_context context;
   krb5_ccache id;
   krb5_address ** addrs;
{
     krb5_error_code ret;
     krb5_address **temp;
     krb5_int32 i, length = 0;

     /* Count the number of components */
     if (addrs) {
	     temp = addrs;
	     while (*temp++)
		     length += 1;
     }

     ret = krb5_fcc_store_int32(context, id, length);
     CHECK(ret);
     for (i=0; i < length; i++) {
	  ret = krb5_fcc_store_addr(context, id, addrs[i]);
	  CHECK(ret);
     }

     return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_keyblock(context, id, keyblock)
   krb5_context context;
   krb5_ccache id;
   krb5_keyblock *keyblock;
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code ret;

     ret = krb5_fcc_store_ui_2(context, id, keyblock->enctype);
     CHECK(ret);
     if (data->version == KRB5_FCC_FVNO_3) {
	 ret = krb5_fcc_store_ui_2(context, id, keyblock->enctype);
	 CHECK(ret);
     }
     ret = krb5_fcc_store_int32(context, id, keyblock->length);
     CHECK(ret);
     return krb5_fcc_write(context, id, (char *) keyblock->contents, keyblock->length);
}

krb5_error_code
krb5_fcc_store_addr(context, id, addr)
   krb5_context context;
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code ret;

     ret = krb5_fcc_store_ui_2(context, id, addr->addrtype);
     CHECK(ret);
     ret = krb5_fcc_store_int32(context, id, addr->length);
     CHECK(ret);
     return krb5_fcc_write(context, id, (char *) addr->contents, addr->length);
}


krb5_error_code
krb5_fcc_store_data(context, id, data)
   krb5_context context;
   krb5_ccache id;
   krb5_data *data;
{
     krb5_error_code ret;

     ret = krb5_fcc_store_int32(context, id, data->length);
     CHECK(ret);
     return krb5_fcc_write(context, id, data->data, data->length);
}

krb5_error_code
krb5_fcc_store_int32(context, id, i)
   krb5_context context;
   krb5_ccache id;
   krb5_int32 i;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    unsigned char buf[4];

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2)) 
	return krb5_fcc_write(context, id, (char *) &i, sizeof(krb5_int32));
    else {
	buf[3] = (unsigned char) (i & 0xFF);
	i >>= 8;
	buf[2] = (unsigned char) (i & 0xFF);
	i >>= 8;
	buf[1] = (unsigned char) (i & 0xFF);
	i >>= 8;
	buf[0] = (unsigned char) (i & 0xFF);
	
	return krb5_fcc_write(context, id, buf, 4);
    }
}

krb5_error_code
krb5_fcc_store_ui_2(context, id, i)
   krb5_context context;
    krb5_ccache id;
    krb5_int32 i;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_ui_2 ibuf;
    unsigned char buf[2];
    
    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2)) {
	ibuf = (krb5_ui_2) i;
	return krb5_fcc_write(context, id, (char *) &ibuf, sizeof(krb5_ui_2));
    } else {
	buf[1] = (unsigned char) (i & 0xFF);
	i >>= 8;
	buf[0] = (unsigned char) (i & 0xFF);
	
	return krb5_fcc_write(context, id, buf, 2);
    }
}
   
krb5_error_code
krb5_fcc_store_octet(context, id, i)
   krb5_context context;
    krb5_ccache id;
    krb5_int32 i;
{
    krb5_octet ibuf;

    ibuf = (krb5_octet) i;
    return krb5_fcc_write(context, id, (char *) &ibuf, 1);
}
   
krb5_error_code
krb5_fcc_store_times(context, id, t)
   krb5_context context;
   krb5_ccache id;
   krb5_ticket_times *t;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code retval;

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_write(context, id, (char *) t, sizeof(krb5_ticket_times));
    else {
	retval = krb5_fcc_store_int32(context, id, t->authtime);
	CHECK(retval);
	retval = krb5_fcc_store_int32(context, id, t->starttime);
	CHECK(retval);
	retval = krb5_fcc_store_int32(context, id, t->endtime);
	CHECK(retval);
	retval = krb5_fcc_store_int32(context, id, t->renew_till);
	CHECK(retval);
	return 0;
    }
}
   
krb5_error_code
krb5_fcc_store_authdata(context, id, a)
   krb5_context context;
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

    ret = krb5_fcc_store_int32(context, id, length);
    CHECK(ret);
    for (i=0; i<length; i++) {
	ret = krb5_fcc_store_authdatum (context, id, a[i]);
	CHECK(ret);
    }
    return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_authdatum (context, id, a)
   krb5_context context;
    krb5_ccache id;
    krb5_authdata *a;
{
    krb5_error_code ret;
    ret = krb5_fcc_store_ui_2(context, id, a->ad_type);
    CHECK(ret);
    ret = krb5_fcc_store_int32(context, id, a->length);
    CHECK(ret);
    return krb5_fcc_write(context, id, (krb5_pointer) a->contents, a->length);
}
/* end of former file/fcc_write.c */
#undef CHECK

krb5_error_code
krb5_fcc_close_file (context, id)
   krb5_context context;
    krb5_ccache id;
{
     int ret;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code retval;

     if (data->fd == -1)
	 return KRB5_FCC_INTERNAL;

     retval = krb5_unlock_file(context, data->fd);
     ret = close (data->fd);
     data->fd = -1;
     if (retval)
	 return retval;
     else
     return (ret == -1) ? krb5_fcc_interpret (context, errno) : 0;
}

krb5_error_code
krb5_fcc_open_file (context, id, mode)
    krb5_context context;
    krb5_ccache id;
    int mode;
{
     krb5_os_context os_ctx = (krb5_os_context)context->os_context;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_ui_2 fcc_fvno;
     krb5_ui_2 fcc_flen;
     krb5_ui_2 fcc_tag;
     krb5_ui_2 fcc_taglen;
     int fd;
     int open_flag, lock_flag;
     krb5_error_code retval = 0;

     if (data->fd != -1) {
	  /* Don't know what state it's in; shut down and start anew.  */
	  (void) krb5_unlock_file(context, data->fd);
	  (void) close (data->fd);
	  data->fd = -1;
     }
     data->mode = mode;
     switch(mode) {
     case FCC_OPEN_AND_ERASE:
	 unlink(data->filename);
	 open_flag = O_CREAT|O_EXCL|O_TRUNC|O_RDWR;
	 break;
     case FCC_OPEN_RDWR:
	 open_flag = O_RDWR;
	 break;
     case FCC_OPEN_RDONLY:
     default:
	 open_flag = O_RDONLY;
	 break;
     }

     fd = THREEPARAMOPEN (data->filename, open_flag | O_BINARY, 0600);
     if (fd == -1)
	  return krb5_fcc_interpret (context, errno);

     if (data->mode == FCC_OPEN_RDONLY)
	lock_flag = KRB5_LOCKMODE_SHARED;
     else 
	lock_flag = KRB5_LOCKMODE_EXCLUSIVE;

     if ((retval = krb5_lock_file(context, fd, lock_flag))) {
	 (void) close(fd);
	 return retval;
     }
	 
     if (mode == FCC_OPEN_AND_ERASE) {
	 /* write the version number */
	 int cnt;

	 fcc_fvno = htons(context->fcc_default_format);
	 data->version = context->fcc_default_format;
	 if ((cnt = write(fd, (char *)&fcc_fvno, sizeof(fcc_fvno))) !=
	     sizeof(fcc_fvno)) {
	     retval = ((cnt == -1) ? krb5_fcc_interpret(context, errno) :
		       KRB5_CC_IO);
	     goto done;
	 }

	 data->fd = fd;
	 
	 if (data->version == KRB5_FCC_FVNO_4) {
	     /* V4 of the credentials cache format allows for header tags */

	     fcc_flen = 0;

	     if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)
		 fcc_flen += (2*sizeof(krb5_ui_2) + 2*sizeof(krb5_int32));

	     /* Write header length */
	     retval = krb5_fcc_store_ui_2(context, id, (krb5_int32)fcc_flen);
	     if (retval) goto done;

	     if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID) {
		 /* Write time offset tag */
		 fcc_tag = FCC_TAG_DELTATIME;
		 fcc_taglen = 2*sizeof(krb5_int32);
		 
		 retval = krb5_fcc_store_ui_2(context,id,(krb5_int32)fcc_tag);
		 if (retval) goto done;
		 retval = krb5_fcc_store_ui_2(context,id,(krb5_int32)fcc_taglen);
		 if (retval) goto done;
		 retval = krb5_fcc_store_int32(context,id,os_ctx->time_offset);
		 if (retval) goto done;
		 retval = krb5_fcc_store_int32(context,id,os_ctx->usec_offset);
		 if (retval) goto done;
	     }
	 }
	 goto done;
     }

     /* verify a valid version number is there */
     if (read(fd, (char *)&fcc_fvno, sizeof(fcc_fvno)) !=
	 sizeof(fcc_fvno)) {
	 retval = KRB5_CC_FORMAT;
	 goto done;
     }
     if ((fcc_fvno != htons(KRB5_FCC_FVNO_4)) &&
	 (fcc_fvno != htons(KRB5_FCC_FVNO_3)) &&
	 (fcc_fvno != htons(KRB5_FCC_FVNO_2)) &&
	 (fcc_fvno != htons(KRB5_FCC_FVNO_1)))
     {
	 retval = KRB5_CCACHE_BADVNO;
	 goto done;
     }

     data->version = ntohs(fcc_fvno);
     data->fd = fd;

     if (data->version == KRB5_FCC_FVNO_4) {
	 char buf[1024];

	 if (krb5_fcc_read_ui_2(context, id, &fcc_flen) ||
	     (fcc_flen > sizeof(buf)))
	 {
	     retval = KRB5_CC_FORMAT;
	     goto done;
	 }

	 while (fcc_flen) {
	     if ((fcc_flen < (2 * sizeof(krb5_ui_2))) ||
		 krb5_fcc_read_ui_2(context, id, &fcc_tag) ||
		 krb5_fcc_read_ui_2(context, id, &fcc_taglen) ||
		 (fcc_taglen > (fcc_flen - 2*sizeof(krb5_ui_2))))
	     {
		 retval = KRB5_CC_FORMAT;
		 goto done;
	     }

	     switch (fcc_tag) {
	     case FCC_TAG_DELTATIME:
		 if (fcc_taglen != 2*sizeof(krb5_int32)) {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 if (!(context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) ||
		     (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID))
		 {
		     if (krb5_fcc_read(context, id, buf, fcc_taglen)) {
			 retval = KRB5_CC_FORMAT;
			 goto done;
		     }
		     break;
		 }
		 if (krb5_fcc_read_int32(context, id, &os_ctx->time_offset) ||
		     krb5_fcc_read_int32(context, id, &os_ctx->usec_offset))
		 {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 os_ctx->os_flags =
		     ((os_ctx->os_flags & ~KRB5_OS_TOFFSET_TIME) |
		      KRB5_OS_TOFFSET_VALID);
		 break;
	     default:
		 if (fcc_taglen && krb5_fcc_read(context,id,buf,fcc_taglen)) {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 break;
	     }
	     fcc_flen -= (2*sizeof(krb5_ui_2) + fcc_taglen);
	 }
     }

done:
     if (retval) {
	 data->fd = -1;
	 (void) krb5_unlock_file(context, fd);
	 (void) close(fd);
     }
     return retval;
}

krb5_error_code
krb5_fcc_skip_header(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code kret;
     krb5_ui_2 fcc_flen;

     lseek(data->fd, sizeof(krb5_ui_2), SEEK_SET);
     if (data->version == KRB5_FCC_FVNO_4) {
	 kret = krb5_fcc_read_ui_2(context, id, &fcc_flen);
	 if (kret) return kret;
	 if(lseek(data->fd, fcc_flen, SEEK_CUR) < 0)
		 return errno;
     }
     return KRB5_OK;
}

krb5_error_code
krb5_fcc_skip_principal(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_error_code kret;
     krb5_principal princ;

     kret = krb5_fcc_read_principal(context, id, &princ);
     if (kret != KRB5_OK)
	  return kret;

     krb5_free_principal(context, princ);
     return KRB5_OK;
}


/*
 * Modifies:
 * id
 *
 * Effects:
 * Creates/refreshes the file cred cache id.  If the cache exists, its
 * contents are destroyed.
 *
 * Errors:
 * system errors
 * permission errors
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_initialize(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal princ;
{
     krb5_error_code kret = 0;
     int reti = 0;

     MAYBE_OPEN(context, id, FCC_OPEN_AND_ERASE);

#ifndef HAVE_FCHMOD
#ifdef HAVE_CHMOD
     reti = chmod(((krb5_fcc_data *) id->data)->filename, S_IREAD | S_IWRITE);
#endif
#else
     reti = fchmod(((krb5_fcc_data *) id->data)->fd, S_IREAD | S_IWRITE);
#endif
     if (reti == -1) {
	 kret = krb5_fcc_interpret(context, errno);
	 MAYBE_CLOSE(context, id, kret);
	 return kret;
     }
     kret = krb5_fcc_store_principal(context, id, princ);

     MAYBE_CLOSE(context, id, kret);
     krb5_change_cache ();
     return kret;
}


/*
 * Modifies:
 * id
 *
 * Effects:
 * Closes the file cache, invalidates the id, and frees any resources
 * associated with the cache.
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_close(context, id)
   krb5_context context;
   krb5_ccache id;
{
     register int closeval = KRB5_OK;

     if (((krb5_fcc_data *) id->data)->fd >= 0)
	     krb5_fcc_close_file(context, id);

     krb5_xfree(((krb5_fcc_data *) id->data)->filename);
     krb5_xfree(((krb5_fcc_data *) id->data));
     krb5_xfree(id);

     return closeval;
}

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_destroy(context, id)
   krb5_context context;
   krb5_ccache id;
{
     struct stat buf;
     unsigned long i, size;
     unsigned int wlen;
     char zeros[BUFSIZ];
     register int ret;
     krb5_error_code kret = 0;
      
     
     if (OPENCLOSE(id)) {
	  ret = THREEPARAMOPEN(((krb5_fcc_data *) id->data)->filename, O_RDWR | O_BINARY, 0);
	  if (ret < 0) {
	      kret = krb5_fcc_interpret(context, errno);
	      goto cleanup;
	  }
	  ((krb5_fcc_data *) id->data)->fd = ret;
     }
     else
	  lseek(((krb5_fcc_data *) id->data)->fd, 0, SEEK_SET);

#ifdef MSDOS_FILESYSTEM
/* "disgusting bit of UNIX trivia" - that's how the writers of NFS describe
** the ability of UNIX to still write to a file which has been unlinked.
** Naturally, the PC can't do this. As a result, we have to delete the file
** after we wipe it clean but that throws off all the error handling code.
** So we have do the work ourselves.
*/
    ret = fstat(((krb5_fcc_data *) id->data)->fd, &buf);
    if (ret == -1) {
        kret = krb5_fcc_interpret(context, errno);
        size = 0;                               /* Nothing to wipe clean */
    } else
        size = (unsigned long) buf.st_size;

    memset(zeros, 0, BUFSIZ);
    while (size > 0) {
        wlen = (int) ((size > BUFSIZ) ? BUFSIZ : size); /* How much to write */
        i = write(((krb5_fcc_data *) id->data)->fd, zeros, wlen);
        if (i < 0) {
            kret = krb5_fcc_interpret(context, errno);
            /* Don't jump to cleanup--we still want to delete the file. */
            break;
        }
        size -= i;                              /* We've read this much */
    }

    if (OPENCLOSE(id)) {
        (void) close(((krb5_fcc_data *)id->data)->fd);
        ((krb5_fcc_data *) id->data)->fd = -1;
    }

    ret = unlink(((krb5_fcc_data *) id->data)->filename);
    if (ret < 0) {
        kret = krb5_fcc_interpret(context, errno);
        goto cleanup;
    }

#else /* MSDOS_FILESYSTEM */

     ret = unlink(((krb5_fcc_data *) id->data)->filename);
     if (ret < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
             kret = ret;
	 }
	 goto cleanup;
     }
     
     ret = fstat(((krb5_fcc_data *) id->data)->fd, &buf);
     if (ret < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 goto cleanup;
     }

     /* XXX This may not be legal XXX */
     size = (unsigned long) buf.st_size;
     memset(zeros, 0, BUFSIZ);
     for (i=0; i < size / BUFSIZ; i++)
	  if (write(((krb5_fcc_data *) id->data)->fd, zeros, BUFSIZ) < 0) {
	      kret = krb5_fcc_interpret(context, errno);
	      if (OPENCLOSE(id)) {
		  (void) close(((krb5_fcc_data *)id->data)->fd);
		  ((krb5_fcc_data *) id->data)->fd = -1;
	      }
	      goto cleanup;
	  }

     wlen = (unsigned int) (size % BUFSIZ);
     if (write(((krb5_fcc_data *) id->data)->fd, zeros, wlen) < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 goto cleanup;
     }

     ret = close(((krb5_fcc_data *) id->data)->fd);
     ((krb5_fcc_data *) id->data)->fd = -1;

     if (ret)
	 kret = krb5_fcc_interpret(context, errno);

#endif /* MSDOS_FILESYSTEM */

  cleanup:
     krb5_xfree(((krb5_fcc_data *) id->data)->filename);
     krb5_xfree(id->data);
     krb5_xfree(id);

     krb5_change_cache ();
     return kret;
}

extern krb5_cc_ops krb5_fcc_ops;

/*
 * Requires:
 * residual is a legal path name, and a null-terminated string
 *
 * Modifies:
 * id
 * 
 * Effects:
 * creates a file-based cred cache that will reside in the file
 * residual.  The cache is not opened, but the filename is reserved.
 * 
 * Returns:
 * A filled in krb5_ccache structure "id".
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 * permission errors
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_resolve (context, id, residual)
   krb5_context context;
   krb5_ccache *id;
   const char *residual;
{
     krb5_ccache lid;
     
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_fcc_ops;
     
     lid->data = (krb5_pointer) malloc(sizeof(krb5_fcc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_fcc_data *) lid->data)->filename = (char *)
	  malloc(strlen(residual) + 1);

     if (((krb5_fcc_data *) lid->data)->filename == NULL) {
	  krb5_xfree(((krb5_fcc_data *) lid->data));
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     /* default to open/close on every trn */
     ((krb5_fcc_data *) lid->data)->flags = KRB5_TC_OPENCLOSE;
     ((krb5_fcc_data *) lid->data)->fd = -1;
     
     /* Set up the filename */
     strcpy(((krb5_fcc_data *) lid->data)->filename, residual);

     lid->magic = KV5M_CCACHE;

     /* other routines will get errors on open, and callers must expect them,
	if cache is non-existent/unusable */
     *id = lid;
     return KRB5_OK;
}

/*
 * Effects:
 * Prepares for a sequential search of the credentials cache.
 * Returns and krb5_cc_cursor to be used with krb5_fcc_next_cred and
 * krb5_fcc_end_seq_get.
 *
 * If the cache is modified between the time of this call and the time
 * of the final krb5_fcc_end_seq_get, the results are undefined.
 *
 * Errors:
 * KRB5_CC_NOMEM
 * system errors
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_start_seq_get(context, id, cursor)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     krb5_fcc_cursor *fcursor;
     krb5_error_code kret = KRB5_OK;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     
     fcursor = (krb5_fcc_cursor *) malloc(sizeof(krb5_fcc_cursor));
     if (fcursor == NULL)
	  return KRB5_CC_NOMEM;
     if (OPENCLOSE(id)) {
	  kret = krb5_fcc_open_file(context, id, FCC_OPEN_RDONLY);
	  if (kret) {
	      krb5_xfree(fcursor);
	      return kret;
	  }
     }

     /* Make sure we start reading right after the primary principal */
     kret = krb5_fcc_skip_header(context, id);
     if (kret) goto done;
     kret = krb5_fcc_skip_principal(context, id);
     if (kret) goto done;

     fcursor->pos = lseek(data->fd, 0, SEEK_CUR);
     *cursor = (krb5_cc_cursor) fcursor;

done:
     MAYBE_CLOSE(context, id, kret);
     return kret;
}

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_fcc_start_seq_get.
 *
 * Modifes:
 * cursor, creds
 * 
 * Effects:
 * Fills in creds with the "next" credentals structure from the cache
 * id.  The actual order the creds are returned in is arbitrary.
 * Space is allocated for the variable length fields in the
 * credentials structure, so the object returned must be passed to
 * krb5_destroy_credential.
 *
 * The cursor is updated for the next call to krb5_fcc_next_cred.
 *
 * Errors:
 * system errors
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_next_cred(context, id, cursor, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
   krb5_creds *creds;
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     krb5_error_code kret;
     krb5_fcc_cursor *fcursor;
     krb5_int32 int32;
     krb5_octet octet;

     memset((char *)creds, 0, sizeof(*creds));

     MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);

     fcursor = (krb5_fcc_cursor *) *cursor;

     kret = lseek(((krb5_fcc_data *) id->data)->fd, fcursor->pos, SEEK_SET);
     if (kret < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 MAYBE_CLOSE(context, id, kret);
	 return kret;
     }

     kret = krb5_fcc_read_principal(context, id, &creds->client);
     TCHECK(kret);
     kret = krb5_fcc_read_principal(context, id, &creds->server);
     TCHECK(kret);
     kret = krb5_fcc_read_keyblock(context, id, &creds->keyblock);
     TCHECK(kret);
     kret = krb5_fcc_read_times(context, id, &creds->times);
     TCHECK(kret);
     kret = krb5_fcc_read_octet(context, id, &octet);
     TCHECK(kret);
     creds->is_skey = octet;
     kret = krb5_fcc_read_int32(context, id, &int32);
     TCHECK(kret);
     creds->ticket_flags = int32;
     kret = krb5_fcc_read_addrs(context, id, &creds->addresses);
     TCHECK(kret);
     kret = krb5_fcc_read_authdata(context, id, &creds->authdata);
     TCHECK(kret);
     kret = krb5_fcc_read_data(context, id, &creds->ticket);
     TCHECK(kret);
     kret = krb5_fcc_read_data(context, id, &creds->second_ticket);
     TCHECK(kret);
     
     fcursor->pos = lseek(((krb5_fcc_data *) id->data)->fd, 0, SEEK_CUR);
     cursor = (krb5_cc_cursor *) fcursor;

lose:
     MAYBE_CLOSE(context, id, kret);		/* won't overwrite kret
					   if already set */
     if (kret != KRB5_OK)
	 krb5_free_cred_contents(context, creds);
     return kret;
}

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_fcc_start_seq_get.
 *
 * Modifies:
 * id, cursor
 *
 * Effects:
 * Finishes sequential processing of the file credentials ccache id,
 * and invalidates the cursor (it must never be used after this call).
 */
/* ARGSUSED */
krb5_error_code KRB5_CALLCONV
krb5_fcc_end_seq_get(context, id, cursor)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     krb5_error_code kret = KRB5_OK;
     
     /* don't close; it may be left open by the caller,
	and if not, fcc_start_seq_get and/or fcc_next_cred will do the
	MAYBE_CLOSE.
     MAYBE_CLOSE(context, id, kret); */
     krb5_xfree((krb5_fcc_cursor *) *cursor);

     return kret;
}

/*
 * Effects:
 * Creates a new file cred cache whose name is guaranteed to be
 * unique.  The name begins with the string TKT_ROOT (from fcc.h).
 * The cache is not opened, but the new filename is reserved.
 *  
 * Returns:
 * The filled in krb5_ccache id.
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 * system errors (from open)
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_generate_new (context, id)
   krb5_context context;
   krb5_ccache *id;
{
     krb5_ccache lid;
     int ret;
     krb5_error_code    retcode = 0;
     char scratch[sizeof(TKT_ROOT)+6+1]; /* +6 for the scratch part, +1 for
					    NUL */
     
     /* Allocate memory */
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_fcc_ops;

     (void) strcpy(scratch, TKT_ROOT);
     (void) strcat(scratch, "XXXXXX");
     mktemp(scratch);

     lid->data = (krb5_pointer) malloc(sizeof(krb5_fcc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     /*
      * The file is initially closed at the end of this call...
      */
     ((krb5_fcc_data *) lid->data)->fd = -1;

     ((krb5_fcc_data *) lid->data)->filename = (char *)
	  malloc(strlen(scratch) + 1);
     if (((krb5_fcc_data *) lid->data)->filename == NULL) {
	  krb5_xfree(((krb5_fcc_data *) lid->data));
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_fcc_data *) lid->data)->flags = 0;
     
     /* Set up the filename */
     strcpy(((krb5_fcc_data *) lid->data)->filename, scratch);

     /* Make sure the file name is reserved */
     ret = THREEPARAMOPEN(((krb5_fcc_data *) lid->data)->filename,
		O_CREAT | O_EXCL | O_WRONLY | O_BINARY, 0);
     if (ret == -1) {
	  retcode = krb5_fcc_interpret(context, errno);
          goto err_out;
     } else {
	  krb5_int16 fcc_fvno = htons(context->fcc_default_format);
	  krb5_int16 fcc_flen = 0;
	  int errsave, cnt;

	  /* Ignore user's umask, set mode = 0600 */
#ifndef HAVE_FCHMOD
#ifdef HAVE_CHMOD
	  chmod(((krb5_fcc_data *) lid->data)->filename, S_IRUSR | S_IWUSR);
#endif
#else
	  fchmod(ret, S_IRUSR | S_IWUSR);
#endif
	  if ((cnt = write(ret, (char *)&fcc_fvno, sizeof(fcc_fvno)))
	      != sizeof(fcc_fvno)) {
	      errsave = errno;
	      (void) close(ret);
	      (void) unlink(((krb5_fcc_data *) lid->data)->filename);
	      retcode = (cnt == -1) ? krb5_fcc_interpret(context, errsave) : KRB5_CC_IO;
              goto err_out;
	  }
	  /* For version 4 we save a length for the rest of the header */
	  if (context->fcc_default_format == KRB5_FCC_FVNO_4) {
	    if ((cnt = write(ret, (char *)&fcc_flen, sizeof(fcc_flen)))
	        != sizeof(fcc_flen)) {
	        errsave = errno;
	        (void) close(ret);
	        (void) unlink(((krb5_fcc_data *) lid->data)->filename);
	        retcode = (cnt == -1) ? krb5_fcc_interpret(context, errsave) : KRB5_CC_IO;
                goto err_out;
	    }
	  }
	  if (close(ret) == -1) {
	      errsave = errno;
	      (void) unlink(((krb5_fcc_data *) lid->data)->filename);
	      retcode = krb5_fcc_interpret(context, errsave);
              goto err_out;
	  }

	  *id = lid;

	  /* default to open/close on every trn - otherwise destroy 
	     will get as to state confused */
	  ((krb5_fcc_data *) lid->data)->flags = KRB5_TC_OPENCLOSE;
      krb5_change_cache ();
	  return KRB5_OK;
     }

err_out:
     krb5_xfree(((krb5_fcc_data *) lid->data)->filename);
     krb5_xfree(((krb5_fcc_data *) lid->data));
     krb5_xfree(lid);
     return retcode;
}

/*
 * Requires:
 * id is a file credential cache
 * 
 * Returns:
 * The name of the file cred cache id.
 */
char * KRB5_CALLCONV
krb5_fcc_get_name (context, id)
   krb5_context context;
   krb5_ccache id;
{
     return (char *) ((krb5_fcc_data *) id->data)->filename;
}

/*
 * Modifies:
 * id, princ
 *
 * Effects:
 * Retrieves the primary principal from id, as set with
 * krb5_fcc_initialize.  The principal is returned is allocated
 * storage that must be freed by the caller via krb5_free_principal.
 *
 * Errors:
 * system errors
 * KRB5_CC_NOMEM
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_get_principal(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal *princ;
{
     krb5_error_code kret = KRB5_OK;

     MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);
     
     /* make sure we're beyond the header */
     kret = krb5_fcc_skip_header(context, id);
     if (kret) goto done;
     kret = krb5_fcc_read_principal(context, id, princ);

done:
     MAYBE_CLOSE(context, id, kret);
     return kret;
}

     
krb5_error_code KRB5_CALLCONV
krb5_fcc_retrieve(context, id, whichfields, mcreds, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
    return krb5_cc_retrieve_cred_default (context, id, whichfields,
					  mcreds, creds);
}


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
krb5_error_code KRB5_CALLCONV
krb5_fcc_store(context, id, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_creds *creds;
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     krb5_error_code ret;

     MAYBE_OPEN(context, id, FCC_OPEN_RDWR);

     /* Make sure we are writing to the end of the file */
     ret = lseek(((krb5_fcc_data *) id->data)->fd, 0, SEEK_END);
     if (ret < 0) {
	  MAYBE_CLOSE_IGNORE(context, id);
	  return krb5_fcc_interpret(context, errno);
     }

     ret = krb5_fcc_store_principal(context, id, creds->client);
     TCHECK(ret);
     ret = krb5_fcc_store_principal(context, id, creds->server);
     TCHECK(ret);
     ret = krb5_fcc_store_keyblock(context, id, &creds->keyblock);
     TCHECK(ret);
     ret = krb5_fcc_store_times(context, id, &creds->times);
     TCHECK(ret);
     ret = krb5_fcc_store_octet(context, id, creds->is_skey);
     TCHECK(ret);
     ret = krb5_fcc_store_int32(context, id, creds->ticket_flags);
     TCHECK(ret);
     ret = krb5_fcc_store_addrs(context, id, creds->addresses);
     TCHECK(ret);
     ret = krb5_fcc_store_authdata(context, id, creds->authdata);
     TCHECK(ret);
     ret = krb5_fcc_store_data(context, id, &creds->ticket);
     TCHECK(ret);
     ret = krb5_fcc_store_data(context, id, &creds->second_ticket);
     TCHECK(ret);

lose:
     MAYBE_CLOSE(context, id, ret);
     krb5_change_cache ();
     return ret;
#undef TCHECK
}
#undef CHECK


/*
 * Requires:
 * id is a cred cache returned by krb5_fcc_resolve or
 * krb5_fcc_generate_new, but has not been opened by krb5_fcc_initialize.
 *
 * Modifies:
 * id
 * 
 * Effects:
 * Sets the operational flags of id to flags.
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_set_flags(context, id, flags)
   krb5_context context;
   krb5_ccache id;
   krb5_flags flags;
{
    /* XXX This should check for illegal combinations, if any.. */
    if (flags & KRB5_TC_OPENCLOSE) {
	/* asking to turn on OPENCLOSE mode */
	if (!OPENCLOSE(id)) {
	    (void) krb5_fcc_close_file (context, id);
	}
    } else {
	/* asking to turn off OPENCLOSE mode, meaning it must be
	   left open.  We open if it's not yet open */
	MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);
    }

    ((krb5_fcc_data *) id->data)->flags = flags;
    return KRB5_OK;
}


krb5_error_code
krb5_fcc_interpret(context, errnum)
     krb5_context context;
     int errnum;
{
    register krb5_error_code retval;
    switch (errnum) {
    case ENOENT:
	retval = KRB5_FCC_NOFILE;
	break;
    case EPERM:
    case EACCES:
    case EISDIR:
    case ENOTDIR:
#ifdef ELOOP
    case ELOOP:				/* XXX */
#endif
#ifdef ETXTBSY
    case ETXTBSY:
#endif
    case EBUSY:
    case EROFS:
	retval = KRB5_FCC_PERM;
	break;
    case EINVAL:
    case EEXIST:			/* XXX */
    case EFAULT:
    case EBADF:
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
#endif
#ifdef EWOULDBLOCK
    case EWOULDBLOCK:
#endif
	retval = KRB5_FCC_INTERNAL;
	break;
#ifdef EDQUOT
    case EDQUOT:
#endif
    case ENOSPC:
    case EIO:
    case ENFILE:
    case EMFILE:
    case ENXIO:
    default:
	retval = KRB5_CC_IO;		/* XXX */
    }
    return retval;
}
#define NEED_WINDOWS

krb5_cc_ops krb5_fcc_ops = {
     0,
     "FILE",
     krb5_fcc_get_name,
     krb5_fcc_resolve,
     krb5_fcc_generate_new,
     krb5_fcc_initialize,
     krb5_fcc_destroy,
     krb5_fcc_close,
     krb5_fcc_store,
     krb5_fcc_retrieve,
     krb5_fcc_get_principal,
     krb5_fcc_start_seq_get,
     krb5_fcc_next_cred,
     krb5_fcc_end_seq_get,
     NULL, /* XXX krb5_fcc_remove, */
     krb5_fcc_set_flags,
};

#if defined(_MSDOS) || defined(_WIN32)

/*
 * krb5_change_cache should be called after the cache changes.
 * A notification message is is posted out to all top level
 * windows so that they may recheck the cache based on the
 * changes made.  We register a unique message type with which
 * we'll communicate to all other processes. 
 */

krb5_error_code 
krb5_change_cache (void) {

    PostMessage(HWND_BROADCAST, krb5_get_notification_message(), 0, 0);

    return 0;
}

KRB5_DLLIMP unsigned int KRB5_CALLCONV
krb5_get_notification_message (void) {
    static unsigned int message = 0;

    if (message == 0)
        message = RegisterWindowMessage(WM_KERBEROS5_CHANGED);

    return message;
}
#else /* _MSDOS || _WIN32 */

krb5_error_code
krb5_change_cache () 
{
    return 0;
}
unsigned int
krb5_get_notification_message ()
{
    return 0;
}

#endif /* _MSDOS || _WIN32 */

krb5_cc_ops krb5_cc_file_ops = {
     0,
     "FILE",
     krb5_fcc_get_name,
     krb5_fcc_resolve,
     krb5_fcc_generate_new,
     krb5_fcc_initialize,
     krb5_fcc_destroy,
     krb5_fcc_close,
     krb5_fcc_store,
     krb5_fcc_retrieve,
     krb5_fcc_get_principal,
     krb5_fcc_start_seq_get,
     krb5_fcc_next_cred,
     krb5_fcc_end_seq_get,
     NULL, /* XXX krb5_fcc_remove, */
     krb5_fcc_set_flags,
};
