/*
 *
 * Copyright (C) 2003, 2007, 2008, 2009 by the Massachusetts Institute of Technology.
 * Copyright (C) 2010 Red Hat, Inc.
 * All rights reserved.
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
 */

#include "k5-int.h"
#include "pkcs11t.h"
#include "sechash.h"
#include "secmodt.h"

/* 512 bits is bigger than anything defined to date */
#define MAX_KEY_LENGTH 64
#define MAX_BLOCK_SIZE 64

/*
 * common nss utils
 */
/* Make sure NSS is properly initialized */
krb5_error_code k5_nss_init(void);

/* import a key into NSS and store the handle in krb5_key */
krb5_error_code
k5_nss_gen_import(krb5_key key, CK_MECHANISM_TYPE mech, 
		        CK_ATTRIBUTE_TYPE operation);
/* clean up an imported key */
void
k5_nss_gen_cleanup(krb5_key key);

/* create a new crypto/hash/sign context from a krb5_key */
PK11Context *
k5_nss_create_context(krb5_key krb_key, CK_MECHANISM_TYPE mechanism,
			CK_ATTRIBUTE_TYPE operation, SECItem * param);

/* mapp and NSS error into a krb5_error_code */
krb5_error_code k5_nss_map_error (int nss_error);
krb5_error_code k5_nss_map_last_error (void);


/*
 * common encryption functions
 */
/* encrypt/decrypt block modes except cts using iov */
krb5_error_code
k5_nss_gen_block_iov(krb5_key key, CK_MECHANISM_TYPE mech, 
		        CK_ATTRIBUTE_TYPE operation,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data);
/* encrypt/decrypt stream modes using iov */
krb5_error_code
k5_nss_gen_stream_iov(krb5_key key, krb5_data *state,
			CK_MECHANISM_TYPE mech, 
		        CK_ATTRIBUTE_TYPE operation,
		        krb5_crypto_iov *data,
		        size_t num_data);
/* encrypt/decrypt block modes using cts */
krb5_error_code
k5_nss_gen_cts_iov(krb5_key key, CK_MECHANISM_TYPE mech, 
		        CK_ATTRIBUTE_TYPE operation,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data);

/* stream state management calls */
krb5_error_code
k5_nss_stream_init_state(krb5_data *new_state);
krb5_error_code
k5_nss_stream_free_state(krb5_data *state);

/*
 * common hash functions
 */
/* all hash modes */
krb5_error_code 
k5_nss_gen_hash(HASH_HashType hashType, const krb5_crypto_iov *data,
			size_t num_data, krb5_data *output);
