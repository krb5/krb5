/*
 * lib/kdb/kdb_xdr.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology. 
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
 */

#include "k5-int.h"
#include <stdio.h>
#include <errno.h>

krb5_error_code
krb5_dbe_create_key_data(context, entry) 
    krb5_context	  context;
    krb5_db_entry	* entry;
{
    if (entry->n_key_data) {
	if ((entry->key_data = (krb5_key_data *)realloc(entry->key_data, 
	         sizeof(krb5_key_data) * (entry->n_key_data + 1))))
    	    memset(entry->key_data + entry->n_key_data,0,sizeof(krb5_key_data));
	else 
	    return ENOMEM;
    } else { 
	if ((entry->key_data = (krb5_key_data *)malloc(sizeof(krb5_key_data))))
    	    memset(entry->key_data, 0, sizeof(krb5_key_data));
	else 
	    return ENOMEM;
    }
    entry->n_key_data++;
    return 0;
}

krb5_dbe_encode_mod_princ_data(context, mod_princ, entry)
    krb5_context	  context;
    krb5_tl_mod_princ	* mod_princ;
    krb5_db_entry	* entry;
{
    krb5_error_code 	  retval;
    krb5_tl_data       ** tl_data;
    krb5_octet		* nextloc;
    char		* unparse_mod_princ;
    int			  unparse_mod_princ_size;

    /* 
     * Allocate *tl_data if necessary otherwise reuse it 
     * Need 04 bytes for date
     * Need XX bytes for string
     */
    if ((retval = krb5_unparse_name(context, mod_princ->mod_princ, 
				   &unparse_mod_princ)))
	return(retval);

    unparse_mod_princ_size = (int) strlen(unparse_mod_princ) + 1;

    if ((nextloc = malloc(unparse_mod_princ_size + 4)) == NULL)
	return ENOMEM;

    /* Find any old versions and delete them. */
    for (tl_data = &(entry->tl_data); *tl_data; 
      	 tl_data = &((*tl_data)->tl_data_next)) {
	if ((*tl_data)->tl_data_type == KRB5_TL_MOD_PRINC) {
	    free((*tl_data)->tl_data_contents);
	    entry->n_tl_data--;
	    break;
	}
    }

    if ((*tl_data) || 
	/* Only zero data if it is freshly allocated */
	((*tl_data) = (krb5_tl_data *)calloc(1, sizeof(krb5_tl_data)))) {
	entry->n_tl_data++;
	(*tl_data)->tl_data_type = KRB5_TL_MOD_PRINC;
	(*tl_data)->tl_data_length = unparse_mod_princ_size + 4;
	(*tl_data)->tl_data_contents = nextloc;

	/* Mod Date */
	krb5_kdb_encode_int32(mod_princ->mod_date, nextloc);
	nextloc += 4;

	/* Mod Princ */
	memcpy(nextloc, unparse_mod_princ, unparse_mod_princ_size);
	return 0;
    }

    free(nextloc);
    return ENOMEM;
}

krb5_dbe_decode_mod_princ_data(context, entry, mod_princ)
    krb5_context	  context;
    krb5_db_entry	* entry;
    krb5_tl_mod_princ  ** mod_princ;
{
    krb5_error_code 	  retval;
    krb5_tl_data        * tl_data;
    krb5_octet		* nextloc;

    retval = 0;
    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next) {
	if (tl_data->tl_data_type == KRB5_TL_MOD_PRINC) {
    	    if ((*mod_princ = malloc(sizeof(krb5_tl_mod_princ))) == NULL)
	  	return ENOMEM;

	    nextloc = tl_data->tl_data_contents;

	    /* Mod Date */
	    krb5_kdb_decode_int32(nextloc, (*mod_princ)->mod_date);
	    nextloc += 4;

	    /* Mod Princ */
    	    if ((retval = krb5_parse_name(context, (const char *) nextloc, 
					 &((*mod_princ)->mod_princ))))
		break;
    	    if ((strlen((char *) nextloc) + 1 + 4) !=
		tl_data->tl_data_length) {
		retval = KRB5_KDB_TRUNCATED_RECORD;
		break;
	    }
	}
    }

    if (retval && (*mod_princ)) 
	free(*mod_princ);
    return retval;
}

krb5_encode_princ_dbmkey(context, key, principal)
    krb5_context context;
    datum  *key;
    krb5_principal principal;
{
    char *princ_name;
    krb5_error_code retval;

    if (!(retval = krb5_unparse_name(context, principal, &princ_name))) {
        /* need to store the NULL for decoding */
        key->dsize = strlen(princ_name)+1;	
        key->dptr = princ_name;
    }
    return(retval);
}

void
krb5_free_princ_dbmkey(context, key)
    krb5_context context;
    datum  *key;
{
    (void) free(key->dptr);
    key->dsize = 0;
    key->dptr = 0;
    return;
}

krb5_error_code
krb5_encode_princ_contents(context, content, entry)
    krb5_context 	  context;
    datum  		* content;
    krb5_db_entry 	* entry;
{
    int 		  unparse_princ_size, i, j;
    char 		* unparse_princ;
    char		* nextloc;
    krb5_tl_data	* tl_data;
    krb5_error_code 	  retval;
    krb5_int16		  psize16;

    krb5_db_entry copy_princ;

    /*
     * Generate one lump of data from the krb5_db_entry.
     * This data must be independent of byte order of the machine,
     * compact and extensible.
     */

    /* 
     * First allocate enough space for all the data. 
     * Need  2 bytes for the length of the base structure
     * then 40 [9 * 4 + 2 * 2] bytes for the base information
     *         [ mkvno, attributes, max_life, max_renewable_life, expiration,
     *	  	 pw_expiration, last_success, last_failed, fail_auth_count ]
     *         [ n_key_data, n_tl_data ]
     * then XX bytes [ e_length ] for the extra data [ e_data ]
     * then XX bytes [ 2 for length + length for string ] for the principal,
     * then (4 [type + length] + tl_data_length) bytes per tl_data
     * then (4 + (4 + key_data_length) per key_data_contents) bytes per key_data
     */
    content->dsize = entry->len + entry->e_length;

    if ((retval = krb5_unparse_name(context, entry->princ, &unparse_princ)))
	return(retval);

    unparse_princ_size = strlen(unparse_princ) + 1;
    content->dsize += unparse_princ_size;
    content->dsize += 2;		

    i = 0;
    /* tl_data is a linked list */
    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next) {
	content->dsize += tl_data->tl_data_length;
	content->dsize += 4; /* type, length */
	i++;
    }

    if (i != entry->n_tl_data) {
	retval = KRB5_KDB_TRUNCATED_RECORD;
	goto epc_error;
    }

    /* key_data is an array */
    for (i = 0; i < entry->n_key_data; i++) {
	content->dsize += 4; /* Version, KVNO */
	for (j = 0; j < entry->key_data[i].key_data_ver; j++) {
	    content->dsize += entry->key_data[i].key_data_length[j];
	    content->dsize += 4; /* type + length */
	}
    }
	
    if ((content->dptr = malloc(content->dsize)) == NULL) {
	retval = ENOMEM;
	goto epc_error;
    }

    /* 
     * Now we go through entry again, this time copying data 
     * These first entries are always saved regaurdless of version
     */
    nextloc = content->dptr;

	/* Base Length */
    krb5_kdb_encode_int16(entry->len, nextloc);
    nextloc += 2;

	/* Master Key Version */
    krb5_kdb_encode_int32(entry->mkvno, nextloc);
    nextloc += 4;

	/* Attributes */
    krb5_kdb_encode_int32(entry->attributes, nextloc);
    nextloc += 4;
  
	/* Max Life */
    krb5_kdb_encode_int32(entry->max_life, nextloc);
    nextloc += 4;
  
	/* Max Renewable Life */
    krb5_kdb_encode_int32(entry->max_renewable_life, nextloc);
    nextloc += 4;
  
	/* When the client expires */
    krb5_kdb_encode_int32(entry->expiration, nextloc);
    nextloc += 4;
  
	/* When its passwd expires */
    krb5_kdb_encode_int32(entry->pw_expiration, nextloc);
    nextloc += 4;
  
	/* Last successful passwd */
    krb5_kdb_encode_int32(entry->last_success, nextloc);
    nextloc += 4;
  
	/* Last failed passwd attempt */
    krb5_kdb_encode_int32(entry->last_failed, nextloc);
    nextloc += 4;
  
	/* # of failed passwd attempt */
    krb5_kdb_encode_int32(entry->fail_auth_count, nextloc);
    nextloc += 4;

	/* # tl_data strutures */
    krb5_kdb_encode_int16(entry->n_tl_data, nextloc);
    nextloc += 2;
  
	/* # key_data strutures */
    krb5_kdb_encode_int16(entry->n_key_data, nextloc);
    nextloc += 2;
  
    	/* Put extended fields here */
    if (entry->len != KRB5_KDB_V1_BASE_LENGTH)
	abort();

	/* Any extra data that this version doesn't understand. */
    if (entry->e_length) {
	memcpy(nextloc, entry->e_data, entry->e_length);
	nextloc += entry->e_length;
    }
  
	/* 
	 * Now we get to the principal.
	 * To squeze a few extra bytes out it is always assumed to come
	 * after the base type.
	 */
    psize16 = (krb5_int16) unparse_princ_size;
    krb5_kdb_encode_int16(psize16, nextloc);
    nextloc += 2;
    (void) memcpy(nextloc, unparse_princ, unparse_princ_size);
    nextloc += unparse_princ_size;

    	/* tl_data is a linked list, of type, legth, contents */
    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next) {
	krb5_kdb_encode_int16(tl_data->tl_data_type, nextloc);
	nextloc += 2;
	krb5_kdb_encode_int16(tl_data->tl_data_length, nextloc);
	nextloc += 2;

	memcpy(nextloc, tl_data->tl_data_contents, tl_data->tl_data_length);
	nextloc += tl_data->tl_data_length;
    }

    	/* key_data is an array */
    for (i = 0; i < entry->n_key_data; i++) {
	krb5_kdb_encode_int16(entry->key_data[i].key_data_ver, nextloc);
	nextloc += 2;
	krb5_kdb_encode_int16(entry->key_data[i].key_data_kvno, nextloc);
	nextloc += 2;

	for (j = 0; j < entry->key_data[i].key_data_ver; j++) {
	    krb5_int16 type = entry->key_data[i].key_data_type[j];
	    krb5_int16 length = entry->key_data[i].key_data_length[j];

    	    krb5_kdb_encode_int16(type, nextloc);
	    nextloc += 2;
    	    krb5_kdb_encode_int16(length, nextloc);
	    nextloc += 2;

	    if (length) {
	        memcpy(nextloc, entry->key_data[i].key_data_contents[j],length);
	        nextloc += length;
	    }
	}
    }
	
epc_error:;
    free(unparse_princ);
    return retval;
}

void
krb5_free_princ_contents(context, contents)
    krb5_context 	  context;
    datum *contents;
{
    free(contents->dptr);
    contents->dsize = 0;
    contents->dptr = 0;
    return;
}

krb5_error_code
krb5_decode_princ_contents(context, content, entry)
    krb5_context 	  context;
    datum  		* content;
    krb5_db_entry 	* entry;
{
    int			  sizeleft, i;
    char 		* nextloc;
    krb5_tl_data       ** tl_data;
    krb5_int16		  i16;

    krb5_principal princ;
    krb5_error_code retval;
    int major_version = 0, minor_version = 0;

    /* Zero out entry and NULL pointers */
    memset(entry, 0, sizeof(krb5_db_entry));

    /*
     * undo the effects of encode_princ_contents.
     *
     * The first part is decoding the base type. If the base type is
     * bigger than the original base type then the additional fields
     * need to be filled in. If the base type is larger than any
     * known base type the additional data goes in e_data.
     */

    /* First do the easy stuff */
    nextloc = content->dptr;
    sizeleft = content->dsize;
    if ((sizeleft -= KRB5_KDB_V1_BASE_LENGTH) < 0) 
	return KRB5_KDB_TRUNCATED_RECORD;

	/* Base Length */
    krb5_kdb_decode_int16(nextloc, entry->len);
    nextloc += 2;

	/* Master Key Version */
    krb5_kdb_decode_int32(nextloc, entry->mkvno);
    nextloc += 4;

	/* Attributes */
    krb5_kdb_decode_int32(nextloc, entry->attributes);
    nextloc += 4;

	/* Max Life */
    krb5_kdb_decode_int32(nextloc, entry->max_life);
    nextloc += 4;

	/* Max Renewable Life */
    krb5_kdb_decode_int32(nextloc, entry->max_renewable_life);
    nextloc += 4;

	/* When the client expires */
    krb5_kdb_decode_int32(nextloc, entry->expiration);
    nextloc += 4;

	/* When its passwd expires */
    krb5_kdb_decode_int32(nextloc, entry->pw_expiration);
    nextloc += 4;

	/* Last successful passwd */
    krb5_kdb_decode_int32(nextloc, entry->last_success);
    nextloc += 4;

	/* Last failed passwd attempt */
    krb5_kdb_decode_int32(nextloc, entry->last_failed);
    nextloc += 4;

	/* # of failed passwd attempt */
    krb5_kdb_decode_int32(nextloc, entry->fail_auth_count);
    nextloc += 4;

	/* # tl_data strutures */
    krb5_kdb_decode_int16(nextloc, entry->n_tl_data);
    nextloc += 2;

    if (entry->n_tl_data < 0)
	return KRB5_KDB_TRUNCATED_RECORD;

	/* # key_data strutures */
    krb5_kdb_decode_int16(nextloc, entry->n_key_data);
    nextloc += 2;

    if (entry->n_key_data < 0)
	return KRB5_KDB_TRUNCATED_RECORD;

	/* Check for extra data */
    if (entry->len > KRB5_KDB_V1_BASE_LENGTH) {
	entry->e_length = entry->len - KRB5_KDB_V1_BASE_LENGTH;
	if ((entry->e_data = (krb5_octet *)malloc(entry->e_length))) {
	    memcpy(entry->e_data, nextloc, entry->e_length);
	    nextloc += entry->e_length;
	} else {
	    return ENOMEM;
	}
    }

    /*
     * Get the principal name for the entry 
     * (stored as a string which gets unparsed.)
     */
    if ((sizeleft -= 2) < 0) {
	retval = KRB5_KDB_TRUNCATED_RECORD;
	goto error_out;
    }

    i = 0;
    krb5_kdb_decode_int16(nextloc, i16);
    i = (int) i16;
    nextloc += 2;

    if ((retval = krb5_parse_name(context, nextloc, &(entry->princ))))
	goto error_out;
    if ((i != (strlen(nextloc) + 1)) || (sizeleft < i)) {
	retval = KRB5_KDB_TRUNCATED_RECORD;
	goto error_out;
    }
    sizeleft -= i;
    nextloc += i;

    	/* tl_data is a linked list */
    tl_data = &entry->tl_data;
    for (i = 0; i < entry->n_tl_data; i++) {
    	if ((sizeleft -= 4) < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	if ((*tl_data = (krb5_tl_data *)
	  malloc(sizeof(krb5_tl_data))) == NULL) {
	    retval = ENOMEM;
	    goto error_out;
	}
	(*tl_data)->tl_data_next = NULL;
	(*tl_data)->tl_data_contents = NULL;
	krb5_kdb_decode_int16(nextloc, (*tl_data)->tl_data_type);
	nextloc += 2;
	krb5_kdb_decode_int16(nextloc, (*tl_data)->tl_data_length);
	nextloc += 2;

    	if ((sizeleft -= (*tl_data)->tl_data_length) < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	if (((*tl_data)->tl_data_contents = (krb5_octet *)
	  malloc((*tl_data)->tl_data_length)) == NULL) {
	    retval = ENOMEM;
	    goto error_out;
	}
	memcpy((*tl_data)->tl_data_contents,nextloc,(*tl_data)->tl_data_length);
	nextloc += (*tl_data)->tl_data_length;
	tl_data = &((*tl_data)->tl_data_next);
    }

    	/* key_data is an array */
    if ((entry->key_data = (krb5_key_data *)
      malloc(sizeof(krb5_key_data) * entry->n_key_data)) == NULL) {
        retval = ENOMEM;
	goto error_out;
    }
    for (i = 0; i < entry->n_key_data; i++) {
	krb5_key_data * key_data;
        int j;

    	if ((sizeleft -= 4) < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	key_data = entry->key_data + i;
	memset(key_data, 0, sizeof(krb5_key_data));
	krb5_kdb_decode_int16(nextloc, key_data->key_data_ver);
	nextloc += 2;
	krb5_kdb_decode_int16(nextloc, key_data->key_data_kvno);
	nextloc += 2;

	/* key_data_ver determins number of elements and how to unparse them. */
	if (key_data->key_data_ver <= KRB5_KDB_V1_KEY_DATA_ARRAY) {
	    for (j = 0; j < key_data->key_data_ver; j++) {
    	        if ((sizeleft -= 4) < 0) {
	            retval = KRB5_KDB_TRUNCATED_RECORD;
	            goto error_out;
	        }
		krb5_kdb_decode_int16(nextloc, key_data->key_data_type[j]);
		nextloc += 2;
		krb5_kdb_decode_int16(nextloc, key_data->key_data_length[j]);
		nextloc += 2;

    	        if ((sizeleft -= key_data->key_data_length[j]) < 0) {
	            retval = KRB5_KDB_TRUNCATED_RECORD;
	            goto error_out;
	        }
	        if (key_data->key_data_length[j]) {
	    	    if ((key_data->key_data_contents[j] = (krb5_octet *)
	    	      malloc(key_data->key_data_length[j])) == NULL) {
	                retval = ENOMEM;
	                goto error_out;
	            }
	            memcpy(key_data->key_data_contents[j], nextloc, 
		           key_data->key_data_length[j]);
	            nextloc += key_data->key_data_length[j];
		}
	    }
	} else {
	    /* This isn't right. I'll fix it later */
	    abort();
	}
    }
    return 0;

error_out:;
    krb5_dbe_free_contents(context, entry);
    return retval;
}
	    
void
krb5_dbe_free_contents(context, entry)
     krb5_context 	  context; 
     krb5_db_entry 	* entry;
{
    krb5_tl_data 	* tl_data_next;
    krb5_tl_data 	* tl_data;
    int i, j;

    if (entry->e_data)
	free(entry->e_data);
    if (entry->princ)
	krb5_free_principal(context, entry->princ);
    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data_next) {
	tl_data_next = tl_data->tl_data_next;
	if (tl_data->tl_data_contents)
	    free(tl_data->tl_data_contents);
	free(tl_data);
    }
    if (entry->key_data) {
    	for (i = 0; i < entry->n_key_data; i++) {
	    for (j = 0; j < entry->key_data[i].key_data_ver; j++) {
	    	if (entry->key_data[i].key_data_length[j]) {
		    if (entry->key_data[i].key_data_contents[j]) {
		        memset(entry->key_data[i].key_data_contents[j], 
			       0, entry->key_data[i].key_data_length[j]);
		    	free (entry->key_data[i].key_data_contents[j]);
		    }
		}
		entry->key_data[i].key_data_contents[j] = NULL;
		entry->key_data[i].key_data_length[j] = 0;
		entry->key_data[i].key_data_type[j] = 0;
	    }
	}
	free(entry->key_data);
    }
    memset(entry, 0, sizeof(*entry));
    return;
}

