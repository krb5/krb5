/* cc_stdio.c - stdio ccache implementation
 * Copyright 2000 MIT blah blah...
 */
/*
If OPENCLOSE is defined, ecah of the functions opens and closes the
file whenever it needs to access it.  Otherwise, the file is opened
once in initialize and closed once is close.

This library depends on ANSI C library routines for file handling.  It
may also have some implicit assumptions about UNIX, but we'll get
those out as much as possible.

If you are running a UNIX system, you probably want to use the
UNIX-based "file" cache package instead of this.

The quasi-BNF grammar for a credentials cache:

file ::= 
	format-vno principal list-of-credentials

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

format-vno ::= <int16>

etc.
 */
/*todo:
Make sure that each time a function returns KRB5_NOMEM, everything
allocated earlier in the function and stack tree is freed.

Overwrite cache file with nulls before removing it.

Check return values and sanity-check parameters more thoroughly.  This
code was derived from UNIX file I/O code, and the conversion of
error-trapping may be incomplete.  Probably lots of bugs dealing with
end-of-file versus other errors.
 */
#include "k5-int.h"
/* start of former stdio/scc-proto.h */
/*
 * lib/krb5/ccache/stdio/scc-proto.h
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Prototypes for File-based credentials cache
 */


#ifndef KRB5_SCC_PROTO__
#define KRB5_SCC_PROTO__

/* scc_close.c */
krb5_error_code krb5_scc_close 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id ));

/* scc_defnam.c */
char *krb5_scc_default_name 
	PROTOTYPE((krb5_context));

/* scc_destry.c */
krb5_error_code krb5_scc_destroy 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id ));

/* scc_eseq.c */
krb5_error_code krb5_scc_end_seq_get 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor ));

/* scc_gennew.c */
krb5_error_code krb5_scc_generate_new 
	PROTOTYPE((krb5_context, 
		   krb5_ccache *id ));

/* scc_getnam.c */
char *krb5_scc_get_name 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id ));

/* scc_gprin.c */
krb5_error_code krb5_scc_get_principal 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_principal *princ ));

/* scc_init.c */
krb5_error_code krb5_scc_initialize 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_principal princ ));

/* scc_maybe.c */
krb5_error_code krb5_scc_close_file 
	PROTOTYPE((krb5_context, 
		   krb5_ccache));
krb5_error_code krb5_scc_open_file 
	PROTOTYPE((krb5_context, 
		   krb5_ccache,
		   int));

/* scc_nseq.c */
krb5_error_code krb5_scc_next_cred 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds ));

/* scc_read.c */
krb5_error_code krb5_scc_read
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_pointer buf,
		   int len));
krb5_error_code krb5_scc_read_principal 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_principal *princ ));
krb5_error_code krb5_scc_read_keyblock 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_keyblock *keyblock ));
krb5_error_code krb5_scc_read_data 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_data *data ));
krb5_error_code krb5_scc_read_int32 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_int32 *i ));
krb5_error_code krb5_scc_read_ui_2 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_ui_2 *i ));
krb5_error_code krb5_scc_read_octet 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_octet *i ));
krb5_error_code krb5_scc_read_times 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_ticket_times *t ));
krb5_error_code krb5_scc_read_addrs 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_address ***));
krb5_error_code krb5_scc_read_addr 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_address *));
krb5_error_code krb5_scc_read_authdata 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_authdata***));
krb5_error_code krb5_scc_read_authdatum 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_authdata*));

/* scc_reslv.c */
krb5_error_code krb5_scc_resolve 
	PROTOTYPE((krb5_context, 
		   krb5_ccache *id , 
		   const char *residual ));

/* scc_retrv.c */
krb5_error_code krb5_scc_retrieve 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds ));

/* scc_sseq.c */
krb5_error_code krb5_scc_start_seq_get 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor ));

/* scc_store.c */
krb5_error_code krb5_scc_store 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_creds *creds ));

/* scc_skip.c */
krb5_error_code krb5_scc_skip_header
	PROTOTYPE((krb5_context, krb5_ccache));
krb5_error_code krb5_scc_skip_principal 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id ));

/* scc_sflags.c */
krb5_error_code krb5_scc_set_flags 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags flags ));

/* scc_ops.c */
extern krb5_cc_ops krb5_scc_ops;

/* scc_write.c */
krb5_error_code krb5_scc_write 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_pointer buf , 
		   int len ));
krb5_error_code krb5_scc_store_principal 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_principal princ ));
krb5_error_code krb5_scc_store_keyblock 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_keyblock *keyblock ));
krb5_error_code krb5_scc_store_data 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_data *data ));
krb5_error_code krb5_scc_store_int32 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_int32 i ));
krb5_error_code krb5_scc_store_ui_2 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_int32 i ));
krb5_error_code krb5_scc_store_octet 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_int32 i ));
krb5_error_code krb5_scc_store_times 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_ticket_times *t ));
krb5_error_code krb5_scc_store_addrs 
	PROTOTYPE((krb5_context, 
		   krb5_ccache , 
		   krb5_address ** ));
krb5_error_code krb5_scc_store_addr 
	PROTOTYPE((krb5_context, 
		   krb5_ccache , 
		   krb5_address * ));
krb5_error_code krb5_scc_store_authdata 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_authdata **));
krb5_error_code krb5_scc_store_authdatum 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_authdata *));

/* scc_errs.c */
krb5_error_code krb5_scc_interpret 
	PROTOTYPE((krb5_context, 
		   int ));

#endif /* KRB5_SCC_PROTO__ */
/* end of former stdio/scc-proto.h */
/* start of former stdio/scc.h */
/*
 * lib/krb5/ccache/stdio/scc.h
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains constant and function declarations used in the
 * file-based credential cache routines.
 */

#ifndef __KRB5_FILE_CCACHE__
#define __KRB5_FILE_CCACHE__

#include <stdio.h>

#define KRB5_OK 0

#define KRB5_SCC_MAXLEN 100

/*
 * SCC version 2 contains type information for principals.  SCC
 * version 1 does not.  The code will accept either, and depending on
 * what KRB5_SCC_DEFAULT_FVNO is set to, it will create version 1 or
 * version 2 SCC caches.
 *
 */

#define KRB5_SCC_FVNO_1   0x0501	/* krb v5, scc v1 */
#define KRB5_SCC_FVNO_2   0x0502	/* krb v5, scc v2 */
#define KRB5_SCC_FVNO_3   0x0503	/* krb v5, scc v3 */
#define KRB5_SCC_FVNO_4   0x0504	/* krb v5, scc v4 */

#define	SCC_OPEN_AND_ERASE	1
#define	SCC_OPEN_RDWR		2
#define	SCC_OPEN_RDONLY		3

/* Credential file header tags.
 * The header tags are constructed as:
 *     krb5_ui_2       tag
 *     krb5_ui_2       len
 *     krb5_octet      data[len]
 * This format allows for older versions of the fcc processing code to skip
 * past unrecognized tag formats.
 */
#define SCC_TAG_DELTATIME	1

#ifndef TKT_ROOT
#define TKT_ROOT "/tmp/tkt"
#endif

/* macros to make checking flags easier */
#define OPENCLOSE(id) (((krb5_scc_data *)id->data)->flags & KRB5_TC_OPENCLOSE)

typedef struct _krb5_scc_data {
     char *filename;
     FILE *file;
     krb5_flags flags;
     char stdio_buffer[BUFSIZ];
     int version;
} krb5_scc_data;

/* An off_t can be arbitrarily complex */
typedef struct _krb5_scc_cursor {
    long pos;
} krb5_scc_cursor;

#define MAYBE_OPEN(context, ID, MODE) \
{									\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_open_ret = krb5_scc_open_file (context, ID,MODE);	\
	if (maybe_open_ret) return maybe_open_ret; } }

#define MAYBE_CLOSE(context, ID, RET) \
{									\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_close_ret = krb5_scc_close_file (context, ID);	\
	if (!(RET)) RET = maybe_close_ret; } }

/* DO NOT ADD ANYTHING AFTER THIS #endif */
#endif /* __KRB5_FILE_CCACHE__ */
/* end of former stdio/scc.h */
/* start of former stdio/scc_read.c */
/*
 * lib/krb5/ccache/stdio/scc_read.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for reading variables from a
 * credentials cache.  These are not library-exported functions.
 */



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
krb5_scc_read(context, id, buf, len)
   krb5_context context;
   krb5_ccache id;
   krb5_pointer buf;
   int len;
{
     int ret;

     errno = 0;
     ret = fread((char *) buf, 1, len, ((krb5_scc_data *) id->data)->file);
     if ((ret == 0) && errno)
	  return krb5_scc_interpret(context, errno);
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
krb5_scc_read_principal(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal *princ;
{
    krb5_scc_data *data = (krb5_scc_data *)id->data;
    krb5_error_code kret;
    register krb5_principal tmpprinc;
    krb5_int32 length, type;
    int i;

    if (data->version == KRB5_SCC_FVNO_1) {
	type = KRB5_NT_UNKNOWN;
    } else {
        /* Read principal type */
        kret = krb5_scc_read_int32(context, id, &type);
        if (kret != KRB5_OK)
	    return kret;
    }

    /* Read the number of components */
    kret = krb5_scc_read_int32(context, id, &length);
    if (kret != KRB5_OK)
	return kret;

    /*
     * DCE includes the principal's realm in the count; the new format
     * does not.
     */
    if (data->version == KRB5_SCC_FVNO_1)
	length--;

    tmpprinc = (krb5_principal) malloc(sizeof(krb5_principal_data));
    if (tmpprinc == NULL)
	return KRB5_CC_NOMEM;
    if (length) {
	    tmpprinc->data = (krb5_data *) malloc(length * sizeof(krb5_data));
	    if (tmpprinc->data == 0) {
		    free((char *)tmpprinc);
		    return KRB5_CC_NOMEM;
	    }
    } else
	    tmpprinc->data = 0;
    tmpprinc->magic = KV5M_PRINCIPAL;
    tmpprinc->length = length;
    tmpprinc->type = type;

    kret = krb5_scc_read_data(context, id, krb5_princ_realm(context, tmpprinc));

    i = 0;
    CHECK(kret);

    for (i=0; i < length; i++) {
	kret = krb5_scc_read_data(context, id, krb5_princ_component(context, tmpprinc, i));
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
krb5_scc_read_addrs(context, id, addrs)
   krb5_context context;
   krb5_ccache id;
   krb5_address ***addrs;
{
     krb5_error_code kret;
     krb5_int32 length;
     int i;

     *addrs = 0;

     /* Read the number of components */
     kret = krb5_scc_read_int32(context, id, &length);
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
	      krb5_free_addresses(context, *addrs);
	      return KRB5_CC_NOMEM;
	  }	  
	  kret = krb5_scc_read_addr(context, id, (*addrs)[i]);
	  CHECK(kret);
     }

     return KRB5_OK;
 errout:
     if (*addrs)
	 krb5_free_addresses(context, *addrs);
     return kret;
}

krb5_error_code
krb5_scc_read_keyblock(context, id, keyblock)
   krb5_context context;
   krb5_ccache id;
   krb5_keyblock *keyblock;
{
     krb5_scc_data *data = (krb5_scc_data *)id->data;
     krb5_error_code kret;
     krb5_ui_2 ui2;
     krb5_int32 int32;

     keyblock->magic = KV5M_KEYBLOCK;
     keyblock->contents = 0;

     kret = krb5_scc_read_ui_2(context, id, &ui2);
     keyblock->enctype = ui2;
     CHECK(kret);
     if (data->version == KRB5_SCC_FVNO_3) {
		/* This works because the old etype is the same as the new enctype. */
	     kret = krb5_scc_read_ui_2(context, id, &ui2);
	     /* keyblock->enctype = ui2; */
	     CHECK(kret);
     }

     kret = krb5_scc_read_int32(context, id, &int32);
     CHECK(kret);
#ifdef _MSDOS
     int32 &= VALID_INT_BITS;    /* Gradient does not write  correctly */     
#else
     if ((int32 & VALID_INT_BITS) != int32)     /* Overflow size_t??? */
	  return KRB5_CC_NOMEM;
#endif
     keyblock->length = int32;
     if ( keyblock->length == 0 )
	     return KRB5_OK;
     keyblock->contents = (unsigned char *) malloc(keyblock->length*
						   sizeof(krb5_octet));
     if (keyblock->contents == NULL)
	  return KRB5_CC_NOMEM;
     
     kret = krb5_scc_read(context, id, keyblock->contents, keyblock->length);
     if (kret)
	 goto errout;

     return KRB5_OK;
 errout:
     if (keyblock->contents)
	 krb5_xfree(keyblock->contents);
     return kret;
}

krb5_error_code
krb5_scc_read_data(context, id, data)
   krb5_context context;
   krb5_ccache id;
   krb5_data *data;
{
     krb5_error_code kret;
     krb5_int32 len;

     data->magic = KV5M_DATA;
     data->data = 0;

     kret = krb5_scc_read_int32(context, id, &len);
     CHECK(kret);
#ifdef _MSDOS
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

     kret = krb5_scc_read(context, id, data->data, data->length);
     CHECK(kret);
     
     data->data[data->length] = 0; /* Null terminate, just in case.... */
     return KRB5_OK;
 errout:
     if (data->data)
	 krb5_xfree(data->data);
     return kret;
}

krb5_error_code
krb5_scc_read_addr(context, id, addr)
   krb5_context context;
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code kret;
     krb5_ui_2 ui2;
     krb5_int32 int32;

     addr->magic = KV5M_ADDRESS;
     addr->contents = 0;

     kret = krb5_scc_read_ui_2(context, id, &ui2);
     CHECK(kret);
     addr->addrtype = ui2;
     
     kret = krb5_scc_read_int32(context, id, &int32);
     CHECK(kret);
#ifdef _MSDOS
     int32 &= VALID_INT_BITS;	/* Gradient DCE does this wrong */
#else
     if ((int32 & VALID_INT_BITS) != int32)     /* Overflow int??? */
	  return KRB5_CC_NOMEM;
#endif
     addr->length = int32;

     if (addr->length == 0)
	     return KRB5_OK;

     addr->contents = (krb5_octet *) malloc(addr->length);
     if (addr->contents == NULL)
	  return KRB5_CC_NOMEM;

     kret = krb5_scc_read(context, id, addr->contents, addr->length);
     CHECK(kret);

     return KRB5_OK;
 errout:
     if (addr->contents)
	 krb5_xfree(addr->contents);
     return kret;
}

krb5_error_code
krb5_scc_read_int32(context, id, i)
   krb5_context context;
   krb5_ccache id;
   krb5_int32 *i;
{
    krb5_scc_data *data = (krb5_scc_data *)id->data;
    krb5_error_code retval;
    unsigned char buf[4];

    if ((data->version == KRB5_SCC_FVNO_1) ||
	(data->version == KRB5_SCC_FVNO_2)) 
	return krb5_scc_read(context, id, (krb5_pointer) i, sizeof(krb5_int32));
    else {
	retval = krb5_scc_read(context, id, buf, 4);
	if (retval)
	    return retval;
	*i = (((((buf[0] << 8) + buf[1]) << 8 ) + buf[2]) << 8) + buf[3];
	return 0;
    }
}

krb5_error_code
krb5_scc_read_ui_2(context, id, i)
   krb5_context context;
   krb5_ccache id;
   krb5_ui_2 *i;
{
    krb5_scc_data *data = (krb5_scc_data *)id->data;
    krb5_error_code retval;
    unsigned char buf[2];
    
    if ((data->version == KRB5_SCC_FVNO_1) ||
	(data->version == KRB5_SCC_FVNO_2))
	return krb5_scc_read(context, id, (krb5_pointer) i, sizeof(krb5_ui_2));
    else {
	retval = krb5_scc_read(context, id, buf, 2);
	if (retval)
	    return retval;
	*i = (buf[0] << 8) + buf[1];
	return 0;
    }
}    

krb5_error_code
krb5_scc_read_octet(context, id, i)
   krb5_context context;
   krb5_ccache id;
   krb5_octet *i;
{
    return krb5_scc_read(context, id, (krb5_pointer) i, 1);
}    


krb5_error_code
krb5_scc_read_times(context, id, t)
   krb5_context context;
   krb5_ccache id;
   krb5_ticket_times *t;
{
    krb5_scc_data *data = (krb5_scc_data *)id->data;
    krb5_error_code retval;
    krb5_int32 i;
    
    if ((data->version == KRB5_SCC_FVNO_1) ||
	(data->version == KRB5_SCC_FVNO_2))
	return krb5_scc_read(context, id, (krb5_pointer) t, sizeof(krb5_ticket_times));
    else {
	retval = krb5_scc_read_int32(context, id, &i);
	CHECK(retval);
	t->authtime = i;
	
	retval = krb5_scc_read_int32(context, id, &i);
	CHECK(retval);
	t->starttime = i;

	retval = krb5_scc_read_int32(context, id, &i);
	CHECK(retval);
	t->endtime = i;

	retval = krb5_scc_read_int32(context, id, &i);
	CHECK(retval);
	t->renew_till = i;
    }
    return 0;
errout:
    return retval;
}

krb5_error_code
krb5_scc_read_authdata(context, id, a)
   krb5_context context;
    krb5_ccache id;
    krb5_authdata ***a;
{
     krb5_error_code kret;
     krb5_int32 length;
     int i;

     *a = 0;

     /* Read the number of components */
     kret = krb5_scc_read_int32(context, id, &length);
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
	      krb5_free_authdata(context, *a);
	      return KRB5_CC_NOMEM;
	  }	  
	  kret = krb5_scc_read_authdatum(context, id, (*a)[i]);
	  CHECK(kret);
     }

     return KRB5_OK;
 errout:
     if (*a)
	 krb5_free_authdata(context, *a);
     return kret;
}

krb5_error_code
krb5_scc_read_authdatum(context, id, a)
   krb5_context context;
    krb5_ccache id;
    krb5_authdata *a;
{
    krb5_error_code kret;
    krb5_int32 int32;
    krb5_ui_2 ui2;
    
    a->magic = KV5M_AUTHDATA;
    a->contents = NULL;

    kret = krb5_scc_read_ui_2(context, id, &ui2);
    CHECK(kret);
    a->ad_type = (krb5_authdatatype)ui2;
    kret = krb5_scc_read_int32(context, id, &int32);
    CHECK(kret);
#ifdef _MSDOS
    int32 &= VALID_INT_BITS;
#else
    if ((int32 & VALID_INT_BITS) != int32)     /* Overflow int??? */
          return KRB5_CC_NOMEM;
#endif
    a->length = int32;
    
    if (a->length == 0 )
	    return KRB5_OK;

    a->contents = (krb5_octet *) malloc(a->length);
    if (a->contents == NULL)
	return KRB5_CC_NOMEM;

    kret = krb5_scc_read(context, id, a->contents, a->length);
    CHECK(kret);
    
     return KRB5_OK;
 errout:
     if (a->contents)
	 krb5_xfree(a->contents);
     return kret;
    
}
/* end of former stdio/scc_read.c */
#undef CHECK
/* start of former stdio/scc_write.c */
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_write_<type>.
 */




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
krb5_scc_write(context, id, buf, len)
   krb5_context context;
   krb5_ccache id;
   krb5_pointer buf;
   int len;
{
     int ret;

     errno = 0;
     ret = fwrite((char *) buf, 1, len, ((krb5_scc_data *)id->data)->file);
     if ((ret == 0) && errno) {
	  return krb5_scc_interpret (context, errno);
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
krb5_scc_store_principal(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal princ;
{
    krb5_scc_data *data = (krb5_scc_data *)id->data;
    krb5_error_code ret;
    krb5_int32 i, length, tmp, type;

    type = krb5_princ_type(context, princ);
    tmp = length = krb5_princ_size(context, princ);

    if (data->version == KRB5_SCC_FVNO_1) {
	/*
	 * DCE-compatible format means that the length count
	 * includes the realm.  (It also doesn't include the
	 * principal type information.)
	 */
	tmp++;
    } else {
	ret = krb5_scc_store_int32(context, id, type);
	CHECK(ret);
    }
    
    ret = krb5_scc_store_int32(context, id, tmp);
    CHECK(ret);

    ret = krb5_scc_store_data(context, id, krb5_princ_realm(context, princ));
    CHECK(ret);

    for (i=0; i < length; i++) {
	ret = krb5_scc_store_data(context, id, 
      krb5_princ_component(context, princ, i));
	CHECK(ret);
    }

    return KRB5_OK;
}

krb5_error_code
krb5_scc_store_addrs(context, id, addrs)
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

     ret = krb5_scc_store_int32(context, id, length);
     CHECK(ret);
     for (i=0; i < length; i++) {
	  ret = krb5_scc_store_addr(context, id, addrs[i]);
	  CHECK(ret);
     }

     return KRB5_OK;
}

krb5_error_code
krb5_scc_store_keyblock(context, id, keyblock)
   krb5_context context;
   krb5_ccache id;
   krb5_keyblock *keyblock;
{
     krb5_scc_data *data = (krb5_scc_data *)id->data;
     krb5_error_code ret;

     ret = krb5_scc_store_ui_2(context, id, keyblock->enctype);
     CHECK(ret);
     if (data->version == KRB5_SCC_FVNO_3) {
	 ret = krb5_scc_store_ui_2(context, id, keyblock->enctype);
	 CHECK(ret);
     }
     ret = krb5_scc_store_int32(context, id, keyblock->length);
     CHECK(ret);
     return krb5_scc_write(context, id, (char *) keyblock->contents, keyblock->length);
}

krb5_error_code
krb5_scc_store_addr(context, id, addr)
   krb5_context context;
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code ret;

     ret = krb5_scc_store_ui_2(context, id, addr->addrtype);
     CHECK(ret);
     ret = krb5_scc_store_int32(context, id, addr->length);
     CHECK(ret);
     return krb5_scc_write(context, id, (char *) addr->contents, addr->length);
}


krb5_error_code
krb5_scc_store_data(context, id, data)
   krb5_context context;
   krb5_ccache id;
   krb5_data *data;
{
     krb5_error_code ret;

     ret = krb5_scc_store_int32(context, id, data->length);
     CHECK(ret);
     return krb5_scc_write(context, id, data->data, data->length);
}

krb5_error_code
krb5_scc_store_int32(context, id, i)
   krb5_context context;
   krb5_ccache id;
   krb5_int32 i;
{
    krb5_scc_data *data = (krb5_scc_data *)id->data;
    unsigned char buf[4];

    if ((data->version == KRB5_SCC_FVNO_1) ||
	(data->version == KRB5_SCC_FVNO_2)) 
	return krb5_scc_write(context, id, (char *) &i, sizeof(krb5_int32));
    else {
	buf[3] = i & 0xFF;
	i >>= 8;
	buf[2] = i & 0xFF;
	i >>= 8;
	buf[1] = i & 0xFF;
	i >>= 8;
	buf[0] = i & 0xFF;
	
	return krb5_scc_write(context, id, buf, 4);
    }
}

krb5_error_code
krb5_scc_store_ui_2(context, id, i)
   krb5_context context;
    krb5_ccache id;
    krb5_int32 i;
{
    krb5_scc_data *data = (krb5_scc_data *)id->data;
    krb5_ui_2 ibuf;
    unsigned char buf[2];
    
    if ((data->version == KRB5_SCC_FVNO_1) ||
	(data->version == KRB5_SCC_FVNO_2)) {
	ibuf = i;
	return krb5_scc_write(context, id, (char *) &ibuf, sizeof(krb5_ui_2));
    } else {
	buf[1] = i & 0xFF;
	i >>= 8;
	buf[0] = i & 0xFF;
	
	return krb5_scc_write(context, id, buf, 2);
    }
}
   
krb5_error_code
krb5_scc_store_octet(context, id, i)
   krb5_context context;
    krb5_ccache id;
    krb5_int32 i;
{
    krb5_octet ibuf;

    ibuf = i;
    return krb5_scc_write(context, id, (char *) &ibuf, 1);
}
   
krb5_error_code
krb5_scc_store_times(context, id, t)
   krb5_context context;
   krb5_ccache id;
   krb5_ticket_times *t;
{
    krb5_scc_data *data = (krb5_scc_data *)id->data;
    krb5_error_code retval;

    if ((data->version == KRB5_SCC_FVNO_1) ||
	(data->version == KRB5_SCC_FVNO_2))
	return krb5_scc_write(context, id, (char *) t, sizeof(krb5_ticket_times));
    else {
	retval = krb5_scc_store_int32(context, id, t->authtime);
	CHECK(retval);
	retval = krb5_scc_store_int32(context, id, t->starttime);
	CHECK(retval);
	retval = krb5_scc_store_int32(context, id, t->endtime);
	CHECK(retval);
	retval = krb5_scc_store_int32(context, id, t->renew_till);
	CHECK(retval);
	return 0;
    }
}
   
krb5_error_code
krb5_scc_store_authdata(context, id, a)
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

    ret = krb5_scc_store_int32(context, id, length);
    CHECK(ret);
    for (i=0; i<length; i++) {
	ret = krb5_scc_store_authdatum (context, id, a[i]);
	CHECK(ret);
    }
    return KRB5_OK;
}

krb5_error_code
krb5_scc_store_authdatum (context, id, a)
   krb5_context context;
    krb5_ccache id;
    krb5_authdata *a;
{
    krb5_error_code ret;
    ret = krb5_scc_store_ui_2(context, id, a->ad_type);
    CHECK(ret);
    ret = krb5_scc_store_int32(context, id, a->length);
    CHECK(ret);
    return krb5_scc_write(context, id, (krb5_pointer) a->contents, a->length);
}
/* end of former stdio/scc_write.c */
/* start of former stdio/scc_maybe.c */
/*
 * lib/krb5/ccache/stdio/scc_maybe.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Copyright 1995 by Cygnus Support.
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
 * This file contains the source code for conditional open/close calls.
 */


#ifdef macintosh
/*
 * Kludge for the Macintosh, since fopen doesn't set errno, but open
 * does...
 */
static FILE *my_fopen(char *path, char *mode)
{
	int	fd, open_flags;
	FILE	*f;

	f = fopen(path, mode);
	if (f)
		return f;
	/*
	 * OK, fopen failed; let's try to figure out why....
	 */
	if (strchr(mode, '+'))
		open_flags = O_RDWR;
	else if (strchr(mode, 'w') || strchr(mode, 'a'))
		open_flags = O_WRONLY;
	else
		open_flags = O_RDONLY;
	if (strchr(mode, 'a'))
		open_flags  |= O_APPEND;

	fd = open(path, open_flags);
	if (fd == -1)
		return NULL;
	/*
	 * fopen failed, but open succeeded?   W*E*I*R*D.....
	 */
	close(fd);
	errno = KRB5_CC_IO;
	
	return NULL;
}
#endif

krb5_error_code
krb5_scc_close_file (context, id)
   krb5_context context;
    krb5_ccache id;
{
     krb5_scc_data *data;
     int ret;
     krb5_error_code retval;

     data = (krb5_scc_data *) id->data;
     if (data->file == (FILE *) NULL)
	 return KRB5_FCC_INTERNAL;
#ifdef ultrix
     errno = 0;
#endif
     ret = fflush (data->file);
#ifdef ultrix
     /* their LIBC refuses to allow an fflush() of a read-only buffer!
	We patch around it by only calling it an error if errno is set by a
	(failed) syscall */
     if (ret == EOF && !errno) ret = 0;
#endif
     memset (data->stdio_buffer, 0, sizeof (data->stdio_buffer));
     if (ret == EOF) {
	  int errsave = errno;
	  (void) krb5_unlock_file(context, fileno(data->file));
	  (void) fclose (data->file);
	  data->file = 0;
	  return krb5_scc_interpret (context, errsave);
     }
     retval = krb5_unlock_file(context, fileno(data->file));
     ret = fclose (data->file);
     data->file = 0;
     if (retval)
	 return retval;
     else
     return ret ? krb5_scc_interpret (context, errno) : 0;
}

krb5_error_code
krb5_scc_open_file (context, id, mode)
    krb5_context context;
    krb5_ccache id;
    int mode;
{
    krb5_os_context os_ctx = (krb5_os_context) context->os_context;
    krb5_scc_data *data = (krb5_scc_data *) id->data;
    char fvno_bytes[2];		/* In nework byte order */
    krb5_ui_2 scc_tag;
    krb5_ui_2 scc_taglen;
    krb5_ui_2 scc_hlen;
    FILE *f;
    char *open_flag;
    krb5_error_code retval = 0;
    
    if (data->file) {
	/* Don't know what state it's in; shut down and start anew.  */
	(void) krb5_unlock_file(context, fileno(data->file));
	(void) fclose (data->file);
	data->file = 0;
    }
#ifdef ANSI_STDIO
    switch(mode) {
    case SCC_OPEN_AND_ERASE:
	unlink(data->filename);
	/* XXX should do an exclusive open here, but no way to do */
	/* this under stdio */
	open_flag = "wb+";
	break;
    case SCC_OPEN_RDWR:
	open_flag = "rb+";
	break;
    case SCC_OPEN_RDONLY:
    default:
	open_flag = "rb";
	break;
    }
#else
    switch(mode) {
    case SCC_OPEN_AND_ERASE:
	unlink(data->filename);
	/* XXX should do an exclusive open here, but no way to do */
	/* this under stdio */
	open_flag = "w+";
	break;
    case SCC_OPEN_RDWR:
	open_flag = "r+";
	break;
    case SCC_OPEN_RDONLY:
    default:
	open_flag = "r";
	break;
    }
#endif

#ifdef macintosh
    f = my_fopen (data->filename, open_flag);
#else
    f = fopen (data->filename, open_flag);
#endif    
    if (!f)
	return krb5_scc_interpret (context, errno);
#ifdef HAVE_SETVBUF
    setvbuf(f, data->stdio_buffer, _IOFBF, sizeof (data->stdio_buffer));
#else
    setbuf (f, data->stdio_buffer);
#endif
    switch (mode) {
    case SCC_OPEN_RDONLY:
	if ((retval = krb5_lock_file(context,fileno(f),KRB5_LOCKMODE_SHARED))){
	    (void) fclose(f);
	    return retval;
	}
	break;
    case SCC_OPEN_RDWR:
    case SCC_OPEN_AND_ERASE:
	if ((retval = krb5_lock_file(context, fileno(f), 
				     KRB5_LOCKMODE_EXCLUSIVE))) {
	    (void) fclose(f);
	    return retval;
	}
	break;
    }
    if (mode == SCC_OPEN_AND_ERASE) {
	/* write the version number */

	data->file = f;
	data->version = context->scc_default_format;
	retval = krb5_scc_store_ui_2(context, id, data->version);
	if (retval) goto done;

	if (data->version == KRB5_SCC_FVNO_4) {
	    scc_hlen = 0;

	    if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)
                 scc_hlen += (2*sizeof(krb5_ui_2) + 2*sizeof(krb5_int32));
 
	    /* Write header length */
	    retval = krb5_scc_store_ui_2(context, id, (krb5_int32)scc_hlen);
	    if (retval) goto done;
 
	    if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID) {
		/* Write time offset tag */
		scc_tag = SCC_TAG_DELTATIME;
		scc_taglen = 2*sizeof(krb5_int32);
                 
		retval = krb5_scc_store_ui_2(context,id,(krb5_int32)scc_tag);
		if (retval) goto done;
		retval = krb5_scc_store_ui_2(context,id,(krb5_int32)scc_taglen);
		if (retval) goto done;
		retval = krb5_scc_store_int32(context,id,os_ctx->time_offset);
		if (retval) goto done;
		retval = krb5_scc_store_int32(context,id,os_ctx->usec_offset);
		if (retval) goto done;
	    }
	}
	goto done;
    }

    /* verify a valid version number is there */
    if (!fread((char *)fvno_bytes, sizeof(fvno_bytes), 1, f))
    {
	retval = KRB5_CC_FORMAT;
	goto done;
    }
    data->version = (fvno_bytes[0] << 8) + fvno_bytes[1];
    if ((data->version != KRB5_SCC_FVNO_1) &&
	(data->version != KRB5_SCC_FVNO_2) &&
	(data->version != KRB5_SCC_FVNO_3) &&
	(data->version != KRB5_SCC_FVNO_4))
    {
	retval = KRB5_CCACHE_BADVNO;
	goto done;
    }

    data->file = f;
    
    if (data->version == KRB5_SCC_FVNO_4) {
	char buf[1024];

	if (krb5_scc_read_ui_2(context, id, &scc_hlen) ||
	    (scc_hlen > sizeof(buf)))
	{
	    retval = KRB5_CC_FORMAT;
	    goto done;
	}
	
	while (scc_hlen) {
	    if ((scc_hlen < (2*sizeof(krb5_ui_2))) ||
		krb5_scc_read_ui_2(context, id, &scc_tag) ||
		krb5_scc_read_ui_2(context, id, &scc_taglen) ||
		(scc_taglen > (scc_hlen - 2*sizeof(krb5_ui_2))))
	    {
		retval = KRB5_CC_FORMAT;
		goto done;
	    }

	    switch (scc_tag) {
	    case SCC_TAG_DELTATIME:
		if (scc_taglen != 2*sizeof(krb5_int32)) {
		    retval = KRB5_CC_FORMAT;
		    goto done;
		}
                 if (!(context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) ||
                     (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID))
                 {
                     if (krb5_scc_read(context, id, buf, scc_taglen)) {
                         retval = KRB5_CC_FORMAT;
                         goto done;
                     }
                     break;
                 }
                 if (krb5_scc_read_int32(context, id, &os_ctx->time_offset) ||
                     krb5_scc_read_int32(context, id, &os_ctx->usec_offset))
                 {
                     retval = KRB5_CC_FORMAT;
                     goto done;
                 }
                 os_ctx->os_flags =
                     ((os_ctx->os_flags & ~KRB5_OS_TOFFSET_TIME) |
                      KRB5_OS_TOFFSET_VALID);
                 break;
	    default:
                 if (scc_taglen && krb5_scc_read(context,id,buf,scc_taglen)) {
                     retval = KRB5_CC_FORMAT;
                     goto done;
                 }
                 break;
	    }
	    scc_hlen -= (2*sizeof(krb5_ui_2) + scc_taglen);
	}
    }

done:
    if (retval)
	if (f) {
	    data->file = 0;
	    (void) krb5_unlock_file(context, fileno(f));
	    (void) fclose(f);
	}
    return retval;
}
/* end of former stdio/scc_maybe.c */
/* start of former stdio/scc_skip.c */
/*
 * lib/krb5/ccache/stdio/scc_skip.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for reading variables from a
 * credentials cache.  These are not library-exported functions.
 */



krb5_error_code
krb5_scc_skip_header(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_error_code kret;
     krb5_scc_data *data = (krb5_scc_data *) id->data;
     krb5_ui_2 scc_flen;

     if (fseek(data->file, sizeof(krb5_ui_2), SEEK_SET))
	 return errno;
     if (data->version == KRB5_SCC_FVNO_4) {
	 kret = krb5_scc_read_ui_2(context, id, &scc_flen);
	 if (kret) return kret;
	 if (fseek(data->file, scc_flen, SEEK_CUR))
	     return errno;
     }
     return KRB5_OK;
}

krb5_error_code
krb5_scc_skip_principal(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_error_code kret;
     krb5_principal princ;

     kret = krb5_scc_read_principal(context, id, &princ);
     if (kret != KRB5_OK)
	  return kret;

     krb5_free_principal(context, princ);
     return KRB5_OK;
}
/* end of former stdio/scc_skip.c */
/* start of former stdio/scc_init.c */
/*
 * lib/krb5/ccache/stdio/scc_init.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_initialize.
 */




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
krb5_error_code
krb5_scc_initialize(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal princ;
{
     krb5_error_code kret;

     kret = krb5_scc_open_file (context, id, SCC_OPEN_AND_ERASE);
     if (kret < 0)
	  return krb5_scc_interpret(context, errno);

#if 0
     kret = fchmod(((krb5_scc_data *) id->data)->fd, S_IREAD | S_IWRITE);
     if (kret == -1) {
	 kret = krb5_scc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     close(((krb5_scc_data *)id->data)->fd);
	     ((krb5_scc_data *) id->data)->fd = -1;
	 }
	 return kret;
     }
#endif
     kret = krb5_scc_store_principal(context, id, princ);

     MAYBE_CLOSE (context, id, kret);
     return kret;
}


/* end of former stdio/scc_init.c */
/* start of former stdio/scc_close.c */
/*
 * lib/krb5/ccache/stdio/scc_close.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_scc_close.
 */




/*
 * Modifies:
 * id
 *
 * Effects:
 * Closes the file cache, invalidates the id, and frees any resources
 * associated with the cache.
 */
krb5_error_code
krb5_scc_close(context, id)
   krb5_context context;
   krb5_ccache id;
{
     register int closeval = KRB5_OK;
     register krb5_scc_data *data = (krb5_scc_data *) id->data;

     if (!OPENCLOSE(id)) {
	 closeval = fclose (data->file);
	 data->file = 0;
	 if (closeval == -1) {
	     closeval = krb5_scc_interpret(context, errno);
	 } else
	     closeval = KRB5_OK;
		 
     }
     krb5_xfree (data->filename);
     krb5_xfree (data);
     krb5_xfree (id);

     return closeval;
}
/* end of former stdio/scc_close.c */
/* start of former stdio/scc_destry.c */
/*
 * lib/krb5/ccache/stdio/scc_destry.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_scc_destroy.
 */




#ifndef SEEK_SET
#define SEEK_SET 0
#endif

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
krb5_error_code krb5_scc_destroy(context, id)
   krb5_context context;
   krb5_ccache id;
{
#if 0
     unsigned long size;
     char zeros[BUFSIZ];
#endif
     krb5_scc_data *data = (krb5_scc_data *) id->data;
     register int ret;
     
     if (!OPENCLOSE(id)) {
	 (void) fclose(data->file);
	 data->file = 0;
     }

     ret = remove (data->filename);
     if (ret < 0) {
	 ret = krb5_scc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) fclose(data->file);
	     data->file = 0;
	 }
	 goto cleanup;
     }

#if 0
     /*
      * Possible future extension: Read entire file to determine
      * length, then write nulls all over it.  This was the UNIX
      * version...
      */
     ret = fstat(fileno(data->file), &buf);
     if (ret < 0) {
	 ret = krb5_scc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) fclose(data->file);
	     data->file = 0;
	 }
	 goto cleanup;
     }

     /* XXX This may not be legal XXX */
     size = (unsigned long) buf.st_size;

     memset (zeros, 0, BUFSIZ);
     for (i=0; i < size / BUFSIZ; i++)
	  if (fwrite(data->file, zeros, BUFSIZ) < 0) {
	      ret = krb5_scc_interpret(context, errno);
	      if (OPENCLOSE(id)) {
		  (void) fclose(data->file);
		  data->file = 0;
	      }
	      goto cleanup;
	  }

     if (fwrite(data->file, zeros, size % BUFSIZ) < 0) {
	 ret = krb5_scc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) fclose(data->file);
	     data->file = 0;
	 }
	 goto cleanup;
     }
     
     ret = fclose(data->file);
     data->file = 0;
#endif

     if (ret)
	 ret = krb5_scc_interpret(context, errno);

  cleanup:
     krb5_xfree(data->filename);
     krb5_xfree(data);
     krb5_xfree(id);

     return ret;
}
/* end of former stdio/scc_destry.c */
/* start of former stdio/scc_reslv.c */
/*
 * lib/krb5/ccache/stdio/scc_reslv.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_scc_resolve.
 */




extern krb5_cc_ops krb5_scc_ops;

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
krb5_error_code
krb5_scc_resolve (context, id, residual)
   krb5_context context;
   krb5_ccache *id;
   const char *residual;
{
     krb5_ccache lid;
     
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_scc_ops;
     
     lid->data = (krb5_pointer) malloc(sizeof(krb5_scc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_scc_data *) lid->data)->filename = (char *)
	  malloc(strlen(residual) + 1);

     if (((krb5_scc_data *) lid->data)->filename == NULL) {
	  krb5_xfree(((krb5_scc_data *) lid->data));
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     /* default to open/close on every trn */
     ((krb5_scc_data *) lid->data)->flags = KRB5_TC_OPENCLOSE;
     ((krb5_scc_data *) lid->data)->file = 0;
     
     /* Set up the filename */
     strcpy(((krb5_scc_data *) lid->data)->filename, residual);

     lid->magic = KV5M_CCACHE;

     /* other routines will get errors on open, and callers must expect them,
	if cache is non-existent/unusable */
     *id = lid;
     return KRB5_OK;
}
/* end of former stdio/scc_reslv.c */
/* start of former stdio/scc_sseq.c */
/*
 * lib/krb5/ccache/stdio/scc_sseq.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_start_seq_get.
 */




/*
 * Effects:
 * Prepares for a sequential search of the credentials cache.
 * Returns and krb5_cc_cursor to be used with krb5_scc_next_cred and
 * krb5_scc_end_seq_get.
 *
 * If the cache is modified between the time of this call and the time
 * of the final krb5_scc_end_seq_get, the results are undefined.
 *
 * Errors:
 * KRB5_CC_NOMEM
 * system errors
 */
krb5_error_code
krb5_scc_start_seq_get(context, id, cursor)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     krb5_scc_cursor *fcursor;
     int ret = 0;
     
     fcursor = (krb5_scc_cursor *) malloc(sizeof(krb5_scc_cursor));
     if (fcursor == NULL)
	  return KRB5_CC_NOMEM;

     /* Make sure we start reading right after the primary principal */
     MAYBE_OPEN (context, id, SCC_OPEN_RDONLY);

     ret = krb5_scc_skip_header(context, id);
     if (ret) goto done;
     ret = krb5_scc_skip_principal(context, id);
     if (ret) goto done;
     
     fcursor->pos = ftell(((krb5_scc_data *) id->data)->file);
     *cursor = (krb5_cc_cursor) fcursor;

done:
     MAYBE_CLOSE (context, id, ret);
     return(ret);
}
/* end of former stdio/scc_sseq.c */
/* start of former stdio/scc_nseq.c */
/*
 * lib/krb5/ccache/stdio/scc_nseq.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_next_cred.
 */




/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_scc_start_seq_get.
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
 * The cursor is updated for the next call to krb5_scc_next_cred.
 *
 * Errors:
 * system errors
 */
krb5_error_code
krb5_scc_next_cred(context, id, cursor, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
   krb5_creds *creds;
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     int ret;
     krb5_error_code kret;
     krb5_scc_cursor *fcursor;
     krb5_int32 int32;
     krb5_octet octet;

#define Z(field)	creds->field = 0
     Z (client);
     Z (server);
     Z (keyblock.contents);
     Z (authdata);
     Z (ticket.data);
     Z (second_ticket.data);
     Z (addresses);
#undef Z

     MAYBE_OPEN (context, id, SCC_OPEN_RDONLY);

     fcursor = (krb5_scc_cursor *) *cursor;
     ret = fseek(((krb5_scc_data *) id->data)->file, fcursor->pos, 0);
     if (ret < 0) {
	 ret = krb5_scc_interpret(context, errno);
	 MAYBE_CLOSE (context, id, ret);
	 return ret;
     }

     kret = krb5_scc_read_principal(context, id, &creds->client);
     TCHECK(kret);
     kret = krb5_scc_read_principal(context, id, &creds->server);
     TCHECK(kret);
     kret = krb5_scc_read_keyblock(context, id, &creds->keyblock);
     TCHECK(kret);
     kret = krb5_scc_read_times(context, id, &creds->times);
     TCHECK(kret);
     kret = krb5_scc_read_octet(context, id, &octet);
     TCHECK(kret);
     creds->is_skey = octet;
     kret = krb5_scc_read_int32(context, id, &int32);
     TCHECK(kret);
     creds->ticket_flags = int32;
     kret = krb5_scc_read_addrs(context, id, &creds->addresses);
     TCHECK(kret);
     kret = krb5_scc_read_authdata (context, id, &creds->authdata);
     TCHECK (kret);
     kret = krb5_scc_read_data(context, id, &creds->ticket);
     TCHECK(kret);
     kret = krb5_scc_read_data(context, id, &creds->second_ticket);
     TCHECK(kret);
     
     fcursor->pos = ftell(((krb5_scc_data *) id->data)->file);
     cursor = (krb5_cc_cursor *) fcursor;

lose:
     if (kret != KRB5_OK) {
	 krb5_free_cred_contents(context, creds);
     }
     MAYBE_CLOSE (context, id, kret);
     return kret;
}
/* end of former stdio/scc_nseq.c */
/* start of former stdio/scc_eseq.c */
/*
 * lib/krb5/ccache/stdio/scc_eseq.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_scc_end_seq_get.
 */



/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_scc_start_seq_get.
 *
 * Modifies:
 * id, cursor
 *
 * Effects:
 * Finishes sequential processing of the file credentials ccache id,
 * and invalidates the cursor (it must never be used after this call).
 */
/* ARGSUSED */
krb5_error_code
krb5_scc_end_seq_get(context, id, cursor)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
    int ret = KRB5_OK;
/*    MAYBE_CLOSE (context, id, ret); */

    krb5_xfree((krb5_scc_cursor *) *cursor);

    return ret;
}


/* end of former stdio/scc_eseq.c */
/* start of former stdio/scc_gennew.c */
/*
 * lib/krb5/ccache/stdio/scc_gennew.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_generate_new.
 */


extern krb5_cc_ops krb5_scc_ops;

/*
 * Effects:
 * Creates a new file cred cache whose name is guaranteed to be
 * unique.  The name begins with the string TKT_ROOT (from scc.h).
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
krb5_error_code
krb5_scc_generate_new (context, id)
   krb5_context context;
   krb5_ccache *id;
{
     krb5_ccache lid;
     FILE *f;
     krb5_error_code	retcode = 0;
     char scratch[sizeof(TKT_ROOT)+6+1]; /* +6 for the scratch part, +1 for
					    NUL */
     
     /* Allocate memory */
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_scc_ops;

     (void) strcpy(scratch, TKT_ROOT);
     (void) strcat(scratch, "XXXXXX");
     mktemp(scratch);

     lid->data = (krb5_pointer) malloc(sizeof(krb5_scc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_scc_data *) lid->data)->filename = (char *)
	  malloc(strlen(scratch) + 1);
     if (((krb5_scc_data *) lid->data)->filename == NULL) {
	  krb5_xfree(((krb5_scc_data *) lid->data));
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_scc_data *) lid->data)->flags = 0;
     ((krb5_scc_data *) lid->data)->file = 0;
     
     /* Set up the filename */
     strcpy(((krb5_scc_data *) lid->data)->filename, scratch);

     /* Make sure the file name is useable */
#if defined(__STDC__) || defined(_MSDOS) || defined(_WIN32)
     f = fopen (((krb5_scc_data *) lid->data)->filename, "wb+");
#else
     f = fopen (((krb5_scc_data *) lid->data)->filename, "w+");
#endif
     if (!f) {
	     retcode = krb5_scc_interpret (context, errno);
	     goto err_out;
     } else {
	 unsigned char scc_fvno[2];

	 scc_fvno[0] = (unsigned char) ((context->scc_default_format >> 8) & 0xFF);
	 scc_fvno[1] = (unsigned char) (context->scc_default_format & 0xFF);

	 if (!fwrite((char *)scc_fvno, sizeof(scc_fvno), 1, f)) {
	     retcode = krb5_scc_interpret(context, errno);
	     (void) fclose(f);
	     (void) remove(((krb5_scc_data *) lid->data)->filename);
	     goto err_out;
	 }
 	 /* For version 4 we save a length for the rest of the header */
          if (context->scc_default_format == KRB5_SCC_FVNO_4) {
	     unsigned char scc_flen[2];
	     scc_flen[0] = 0;
	     scc_flen[1] = 0;
	     if (!fwrite((char *)scc_flen, sizeof(scc_flen), 1, f)) {
	        retcode = krb5_scc_interpret(context, errno);
	        (void) fclose(f);
	        (void) remove(((krb5_scc_data *) lid->data)->filename);
                goto err_out;
            }
	 }
	 if (fclose(f) == EOF) {
	     retcode = krb5_scc_interpret(context, errno);
	     (void) remove(((krb5_scc_data *) lid->data)->filename);
	     goto err_out;
	 }
	 *id = lid;
	 return KRB5_OK;
     }
err_out:
     krb5_xfree(((krb5_scc_data *) lid->data)->filename);
     krb5_xfree(((krb5_scc_data *) lid->data));
     krb5_xfree(lid);
     return retcode;
}
/* end of former stdio/scc_gennew.c */
/* start of former stdio/scc_getnam.c */
/*
 * lib/krb5/ccache/stdio/scc_getnam.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_scc_get_name.
 */




/*
 * Requires:
 * id is a file credential cache
 * 
 * Returns:
 * The name of the file cred cache id.
 */
char *
krb5_scc_get_name (context, id)
   krb5_context context;
   krb5_ccache id;
{
     return (char *) ((krb5_scc_data *) id->data)->filename;
}
/* end of former stdio/scc_getnam.c */
/* start of former stdio/scc_gprin.c */
/*
 * lib/krb5/ccache/stdio/scc_gprin.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_get_principal.
 */



/*
 * Modifies:
 * id, princ
 *
 * Effects:
 * Retrieves the primary principal from id, as set with
 * krb5_scc_initialize.  The principal is returned is allocated
 * storage that must be freed by the caller via krb5_free_principal.
 *
 * Errors:
 * system errors
 * KRB5_CC_NOMEM
 */
krb5_error_code
krb5_scc_get_principal(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal *princ;
{
     krb5_error_code kret;

     MAYBE_OPEN (context, id, SCC_OPEN_RDONLY);

     kret = krb5_scc_skip_header(context, id);
     if (kret) goto done;

     kret = krb5_scc_read_principal(context, id, princ);

done:
     MAYBE_CLOSE (context, id, kret);
     return kret;
}
/* end of former stdio/scc_gprin.c */
/* start of former stdio/scc_retrv.c */
/*
 * lib/krb5/ccache/stdio/scc_retrv.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_retrieve.
 */

#if 0


#define set(bits) (whichfields & bits)
#define flags_match(a,b) (((a) & (b)) == (a))

static krb5_boolean
times_match(t1, t2)
register const krb5_ticket_times *t1;
register const krb5_ticket_times *t2;
{
    if (t1->renew_till) {
	if (t1->renew_till > t2->renew_till)
	    return FALSE;		/* this one expires too late */
    }
    if (t1->endtime) {
	if (t1->endtime > t2->endtime)
	    return FALSE;		/* this one expires too late */
    }
    /* only care about expiration on a times_match */
    return TRUE;
}

static krb5_boolean
times_match_exact (t1, t2)
    register const krb5_ticket_times *t1, *t2;
{
    return (t1->authtime == t2->authtime
	    && t1->starttime == t2->starttime
	    && t1->endtime == t2->endtime
	    && t1->renew_till == t2->renew_till);
}

static krb5_boolean
standard_fields_match(context, mcreds, creds)
   krb5_context context;
register const krb5_creds *mcreds, *creds;
{
    return (krb5_principal_compare(context, mcreds->client,creds->client) &&
	    krb5_principal_compare(context, mcreds->server,creds->server));
}

/* only match the server name portion, not the server realm portion */

static krb5_boolean
srvname_match(context, mcreds, creds)
   krb5_context context;
register const krb5_creds *mcreds, *creds;
{
    krb5_boolean retval;
    krb5_principal_data p1, p2;
    
    retval = krb5_principal_compare(context, mcreds->client,creds->client);
    if (retval != TRUE)
	return retval;
    /*
     * Hack to ignore the server realm for the purposes of the compare.
     */
    p1 = *mcreds->server;
    p2 = *creds->server;
    p1.realm = p2.realm;
    return krb5_principal_compare(context, &p1, &p2);
}


static krb5_boolean
authdata_match(mdata, data)
    krb5_authdata *const *mdata, *const *data;
{
    const krb5_authdata *mdatap, *datap;

    if (mdata == data)
	return TRUE;

    if (mdata == NULL)
	return *data == NULL;

    if (data == NULL)
	return *mdata == NULL;

    while ((mdatap = *mdata)
	   && (datap = *data)
	   && mdatap->ad_type == datap->ad_type
	   && mdatap->length == datap->length
	   && !memcmp ((char *) mdatap->contents, (char *) datap->contents,
		       datap->length)) {
	mdata++;
	data++;
    }

    return !*mdata && !*data;
}

static krb5_boolean
data_match(data1, data2)
register const krb5_data *data1, *data2;
{
    if (!data1) {
	if (!data2)
	    return TRUE;
	else
	    return FALSE;
    }
    if (!data2) return FALSE;

    if (data1->length != data2->length)
	return FALSE;
    else
	return memcmp(data1->data, data2->data, data1->length) ? FALSE : TRUE;
}


/*
 * Effects:
 * Searches the file cred cache is for a credential matching mcreds,
 * with the fields specified by whichfields.  If one if found, it is
 * returned in creds, which should be freed by the caller with
 * krb5_free_credentials().
 * 
 * The fields are interpreted in the following way (all constants are
 * preceded by KRB5_TC_).  MATCH_IS_SKEY requires the is_skey field to
 * match exactly.  MATCH_TIMES requires the requested lifetime to be
 * at least as great as that specified; MATCH_TIMES_EXACT requires the
 * requested lifetime to be exactly that specified.  MATCH_FLAGS
 * requires only the set bits in mcreds be set in creds;
 * MATCH_FLAGS_EXACT requires all bits to match.
 *
 * Errors:
 * system errors
 * permission errors
 * KRB5_CC_NOMEM
 */
krb5_error_code
krb5_scc_retrieve(context, id, whichfields, mcreds, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
     /* This function could be considerably faster if it kept indexing */
     /* information.. sounds like a "next version" idea to me. :-) */

     krb5_cc_cursor cursor;
     krb5_error_code kret;
     krb5_creds fetchcreds;

     kret = krb5_scc_start_seq_get(context, id, &cursor);
     if (kret != KRB5_OK)
	  return kret;

     while ((kret = krb5_scc_next_cred(context, id, &cursor, &fetchcreds)) == KRB5_OK) {
	  if (((set(KRB5_TC_MATCH_SRV_NAMEONLY) &&
		   srvname_match(context, mcreds, &fetchcreds)) ||
	       standard_fields_match(context, mcreds, &fetchcreds))
	      &&
	      (! set(KRB5_TC_MATCH_IS_SKEY) ||
	       mcreds->is_skey == fetchcreds.is_skey)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS_EXACT) ||
	       mcreds->ticket_flags == fetchcreds.ticket_flags)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS) ||
	       flags_match(mcreds->ticket_flags, fetchcreds.ticket_flags))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES_EXACT) ||
	       times_match_exact(&mcreds->times, &fetchcreds.times))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES) ||
	       times_match(&mcreds->times, &fetchcreds.times))
	      &&
	      (! set(KRB5_TC_MATCH_AUTHDATA) ||
	       authdata_match (mcreds->authdata, fetchcreds.authdata))
	      &&
	      (! set(KRB5_TC_MATCH_2ND_TKT) ||
	       data_match (&mcreds->second_ticket, &fetchcreds.second_ticket))
	      &&
	      ((! set(KRB5_TC_MATCH_KTYPE))||
		  (mcreds->keyblock.enctype == fetchcreds.keyblock.enctype))
	      )
	  {
	       krb5_scc_end_seq_get(context, id, &cursor);
	       *creds = fetchcreds;
	       return KRB5_OK;
	  }

	  /* This one doesn't match */
	  krb5_free_cred_contents(context, &fetchcreds);
     }

     /* If we get here, a match wasn't found */
     krb5_scc_end_seq_get(context, id, &cursor);
     return KRB5_CC_NOTFOUND;
}

#else


krb5_error_code KRB5_CALLCONV
krb5_scc_retrieve(context, id, whichfields, mcreds, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
    return krb5_cc_retrieve_cred_default (context, id, whichfields,
					  mcreds, creds);
}

#endif
/* end of former stdio/scc_retrv.c */
/* start of former stdio/scc_store.c */
/*
 * lib/krb5/ccache/stdio/scc_store.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_store.
 */




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
krb5_error_code
krb5_scc_store(context, id, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_creds *creds;
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     krb5_error_code ret;

     /* Make sure we are writing to the end of the file */
     MAYBE_OPEN (context, id, SCC_OPEN_RDWR);

     ret = fseek(((krb5_scc_data *) id->data)->file, 0, 2);
     if (ret < 0)
	  return krb5_scc_interpret(context, errno);

     ret = krb5_scc_store_principal(context, id, creds->client);
     TCHECK(ret);
     ret = krb5_scc_store_principal(context, id, creds->server);
     TCHECK(ret);
     ret = krb5_scc_store_keyblock(context, id, &creds->keyblock);
     TCHECK(ret);
     ret = krb5_scc_store_times(context, id, &creds->times);
     TCHECK(ret);
     ret = krb5_scc_store_octet(context, id, creds->is_skey);
     TCHECK(ret);
     ret = krb5_scc_store_int32(context, id, creds->ticket_flags);
     TCHECK(ret);
     ret = krb5_scc_store_addrs(context, id, creds->addresses);
     TCHECK(ret);
     ret = krb5_scc_store_authdata(context, id, creds->authdata);
     TCHECK(ret);
     ret = krb5_scc_store_data(context, id, &creds->ticket);
     TCHECK(ret);
     ret = krb5_scc_store_data(context, id, &creds->second_ticket);
     TCHECK(ret);

lose:

     MAYBE_CLOSE (context, id, ret);
     return ret;
#undef TCHECK
}
/* end of former stdio/scc_store.c */
/* start of former stdio/scc_sflags.c */
/*
 * lib/krb5/ccache/stdio/scc_sflags.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_set_flags.
 */




/*
 * Requires:
 * id is a cred cache returned by krb5_scc_resolve or
 * krb5_scc_generate_new, but has not been opened by krb5_scc_initialize.
 *
 * Modifies:
 * id
 * 
 * Effects:
 * Sets the operational flags of id to flags.
 */
krb5_error_code
krb5_scc_set_flags(context, id, flags)
   krb5_context context;
   krb5_ccache id;
   krb5_flags flags;
{
    krb5_error_code ret = 0;

    /* XXX This should check for illegal combinations, if any.. */
    if (flags & KRB5_TC_OPENCLOSE) {
	/* asking to turn on OPENCLOSE mode */
	if (!OPENCLOSE(id))
	    ret = krb5_scc_close_file (context, id);
    } else {
	/* asking to turn off OPENCLOSE mode, meaning it must be
	   left open.  We open if it's not yet open */
	if (OPENCLOSE(id)) {
	    ret = krb5_scc_open_file (context, id, SCC_OPEN_RDWR);
	}
    }

    ((krb5_scc_data *) id->data)->flags = flags;
    return ret;
}

/* end of former stdio/scc_sflags.c */
/* start of former stdio/scc_errs.c */
/*
 * lib/krb5/ccache/stdio/scc_errs.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * error code interpretation routine
 */




krb5_error_code
krb5_scc_interpret(context, errnum)
   krb5_context context;
int errnum;
{
    register int retval;
    switch (errnum) {
#ifdef ELOOP
    case ELOOP:				/* Bad symlink is like no file. */
#endif
    case ENOENT:
	retval = KRB5_FCC_NOFILE;
	break;
    case EPERM:
    case EACCES:
#ifdef EISDIR
    case EISDIR:			/* Mac doesn't have EISDIR */
#endif
    case ENOTDIR:
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
/* end of former stdio/scc_errs.c */
/* start of former stdio/scc_ops.c */
/*
 * lib/krb5/ccache/stdio/scc_ops.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the structure krb5_scc_ops.
 */




krb5_cc_ops krb5_scc_ops = {
     0,
     "STDIO",
     krb5_scc_get_name,
     krb5_scc_resolve,
     krb5_scc_generate_new,
     krb5_scc_initialize,
     krb5_scc_destroy,
     krb5_scc_close,
     krb5_scc_store,
     krb5_scc_retrieve,
     krb5_scc_get_principal,
     krb5_scc_start_seq_get,
     krb5_scc_next_cred,
     krb5_scc_end_seq_get,
     NULL, /* XXX krb5_scc_remove, */
     krb5_scc_set_flags,
};




     



/* end of former stdio/scc_ops.c */
/* start of former stdio/scc_defops.c */
/*
 * lib/krb5/ccache/stdio/scc_defops.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the structure krb5_cc_dfl_ops.
 */




krb5_cc_ops krb5_cc_stdio_ops = {
     0,
     "STDIO",
     krb5_scc_get_name,
     krb5_scc_resolve,
     krb5_scc_generate_new,
     krb5_scc_initialize,
     krb5_scc_destroy,
     krb5_scc_close,
     krb5_scc_store,
     krb5_scc_retrieve,
     krb5_scc_get_principal,
     krb5_scc_start_seq_get,
     krb5_scc_next_cred,
     krb5_scc_end_seq_get,
     NULL, /* XXX krb5_scc_remove, */
     krb5_scc_set_flags,
};
/* end of former stdio/scc_defops.c */
