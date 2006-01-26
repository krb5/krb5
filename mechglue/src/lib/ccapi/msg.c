/* $Copyright:
 *
 * Copyright 2004 by the Massachusetts Institute of Technology.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require a
 * specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and distribute
 * this software and its documentation for any purpose and without fee is
 * hereby granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of M.I.T. not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  Furthermore if you
 * modify this software you must label your software as modified software
 * and not distribute it in such a fashion that it might be confused with
 * the original MIT software. M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * Individual source code files are copyright MIT, Cygnus Support,
 * OpenVision, Oracle, Sun Soft, FundsXpress, and others.
 * 
 * Project Athena, Athena, Athena MUSE, Discuss, Hesiod, Kerberos, Moira,
 * and Zephyr are trademarks of the Massachusetts Institute of Technology
 * (MIT).  No commercial use of these trademarks may be made without prior
 * written permission of MIT.
 * 
 * "Commercial use" means use of a name in a product or other for-profit
 * manner.  It does NOT prevent a commercial firm from referring to the MIT
 * trademarks in order to convey information (although in doing so,
 * recognition of their trademark status should be given).
 * $
 */

/*
 * Verifiable, extensible message format.
 */

#include "CredentialsCache.h"
#include "msg.h"
#include "datastore.h"

#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>

/**
 * cci_msg_new()
 *
 * Purpose: Allocate and initialize a new cc_msg_t structure
 *
 * Return:  non-NULL, the msg
 *          NULL, failure
 *
 * Errors:  ccErrNoMem
 *
 */
cc_int32
cci_msg_new(cc_uint32 type, cc_msg_t** msgpp) 
{
    // type should be validated.  If invalid set error to ccErrBadParam
    cc_msg_t* msg;
    
    if ( type > CC_MSG_MAX_TYPE || msgpp == NULL )
        return ccErrBadParam;

    msg = (cc_msg_t*)malloc(sizeof(cc_msg_t));
    if (msg == NULL)
        return ccErrNoMem;

    msg->type = type;
    msg->flat = NULL;
    msg->header = NULL;
    msg->flat_len = 0;
    msg->header_len = 0;
    msg->magic = 0;
    cci_generic_list_new(&msg->data_blobs);
    if (msg->data_blobs == NULL) {
        // pass on error from previous call
        free(msg);
        return ccErrNoMem;
    }

    *msgpp = msg;     
    return ccNoError;
}

/**
 * cci_msg_calc_header_size()
 *
 * Purpose: Calculates the size of the header
 *
 * Return:  the size in bytes
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32
cci_msg_calc_header_size(cc_msg_t* msg, cc_uint32 * lenp) 
{
    int header_len = 12; /* header size, entire size, type */

    if ( msg == NULL || lenp == NULL )
        return ccErrBadParam;

    header_len += msg->header_len;
    *lenp = header_len;
    return ccNoError;
}

/**
 * cci_msg_calc_size()
 *
 * Purpose: Calculates the size of the message
 *          (does not include the magic bytes)
 *
 * Return:  the size in bytes
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32 
cci_msg_calc_size(cc_msg_t* msg, cc_uint32 * lenp) 
{
    cc_uint32 flat_len;
    cc_generic_list_node_t* gen_node;
    cc_generic_iterate_t* gen_iterator;
	cc_int32 code;

    if ( msg == NULL || lenp == NULL ) 
        return ccErrBadParam;

    code = cci_msg_calc_header_size(msg, &flat_len);
    if (code != ccNoError)
        goto bad;

    code = cci_generic_list_iterator(msg->data_blobs, &gen_iterator);
    if ( code != ccNoError )
        goto bad;

    while (cci_generic_iterate_has_next(gen_iterator)) {
        code = cci_generic_iterate_next(gen_iterator, &gen_node);
        if (code != ccNoError)
            break;
        flat_len += gen_node->len + BLOB_LEN;
    }
    cci_generic_free_iterator(gen_iterator);
    if (code != ccNoError)
        goto bad;

    flat_len += MAGIC_HEAD_LEN + MAGIC_DATA_LEN;
    *lenp = flat_len;

  bad:
    return code;
}

/**
 * cci_msg_add_data_blob()
 *
 * Purpose: Adds 'len' bytes of data to the msg
 *
 * Return: 
 *
 * Errors: 
 *
 */
cc_int32 
cci_msg_add_data_blob(cc_msg_t* msg, void *data, cc_uint32 len, cc_uint32 *lenp) 
{
    cc_int32 code;

    if (msg == NULL || data == NULL || len <= 0 || lenp == NULL)
        return ccErrBadParam;

    code = cci_generic_list_append(msg->data_blobs, data, len, NULL);
    if ( code != ccNoError )
        return code;
    return cci_msg_calc_blob_pos(msg, data, len, lenp);
}

/**
 * cc_msg_
 *
 * Purpose:
 *
 * Return: 
 *
 * Errors: 
 *
 */
cc_int32 
cci_msg_calc_blob_pos(cc_msg_t* msg, void *data, cc_uint32 len, cc_uint32 * posp) 
{
    cc_uint32 pos;
    cc_generic_list_node_t* gen_node;
    cc_generic_iterate_t* gen_iterator;
    cc_int32 code;

    code = cci_msg_calc_header_size(msg, &pos);
    pos += sizeof(cc_uint32); /*+ sizeof(cc_uint32) for magic*/

    code = cci_generic_list_iterator(msg->data_blobs, &gen_iterator);
    while (cci_generic_iterate_has_next(gen_iterator)) {
        code = cci_generic_iterate_next(gen_iterator, &gen_node);
        if (gen_node->len != len && gen_node->data != data) {
            pos += gen_node->len + sizeof(cc_uint32);
        } else {
            cci_generic_free_iterator(gen_iterator);
            *posp = pos + sizeof(cc_uint32);
            return ccNoError;
        }
    }
    
    cci_generic_free_iterator(gen_iterator);
    return ccIteratorEnd;
}

/**
 * cc_msg_
 *
 * Purpose:
 *
 * Return: 
 *
 * Errors: 
 *
 */
cc_int32 
cci_msg_add_header(cc_msg_t* msg, void *header, cc_uint32 header_len) 
{
    if ( msg == NULL || header == NULL )
        return ccErrBadParam;

    msg->header = header;
    msg->header_len = header_len;
    return ccNoError;
}


/**
 * cc_msg_
 *
 * Purpose:
 *
 * Return: 
 *
 * Errors: 
 *
 */
cc_int32
cci_msg_flatten(cc_msg_t* msg, void **flatpp) 
{
    cc_generic_list_node_t* gen_node;
    cc_generic_iterate_t* gen_iterator;
    char *cur_pos;
    cc_uint32 zero = 0;
    cc_uint32 magic = 0;
    cc_uint32 msg_len;
    cc_int32 code;

    if (msg == NULL || flatpp == NULL)
        return ccErrBadParam;

    code = cci_msg_calc_size(msg,&msg->flat_len);
    if ( code != ccNoError )
        return code;

    if (msg->flat_len > CC_MSG_MAX_SIZE)
        return ccErrBadParam;

    msg->flat = (void *)malloc(msg->flat_len);
    if (msg->flat == NULL)
        return ccErrNoMem;
    
    cur_pos = msg->flat;

    memcpy(cur_pos,&msg->header_len,sizeof(cc_uint32));
    cur_pos+=sizeof(cc_uint32);

    memcpy(cur_pos,&msg->flat_len,sizeof(cc_uint32));
    cur_pos+=sizeof(cc_uint32);

    memcpy(cur_pos,&msg->type,sizeof(cc_uint32));
    cur_pos+=sizeof(cc_uint32);

    memcpy(cur_pos, msg->header, msg->header_len);
    cur_pos += msg->header_len;

    memcpy(cur_pos, &zero, sizeof(cc_uint32)); /*will be magic number later*/
    cur_pos += sizeof(cc_uint32);

    code = cci_generic_list_iterator(msg->data_blobs,&gen_iterator);
    if ( code != ccNoError ) {
        free(msg->flat);
        return code;
    }

    while (cci_generic_iterate_has_next(gen_iterator)) {
        code = cci_generic_iterate_next(gen_iterator, &gen_node);
        if (code != ccNoError) {
            free(gen_iterator);
            free(msg->flat);
            return code;
        }
        memcpy(cur_pos, &gen_node->len, sizeof(cc_uint32));
        cur_pos+=sizeof(cc_uint32);
		
        memcpy(cur_pos, gen_node->data, gen_node->len);
        cur_pos += gen_node->len;
    }
    free(gen_iterator);

    memcpy(cur_pos, &zero, sizeof(cc_uint32)); /*magic number will go here later*/
    cur_pos += sizeof(cc_uint32);

    if (cur_pos - (char *)msg->flat != msg->flat_len) {
        printf("ERRORR cur_pos - msg->flat = %d\n",msg->flat_len);
    }

    cci_msg_calc_magic(msg->flat, msg->flat_len, &magic);
    printf("magic = %d\n",magic);
	
    cci_msg_calc_header_size(msg, &msg_len);
    memcpy((char *)msg->flat + msg_len, &magic, sizeof(cc_uint32));
    memcpy((char *)msg->flat + msg->flat_len - sizeof(cc_uint32), &magic, sizeof(cc_uint32));

    if ( flatpp != NULL )
        *flatpp = msg->flat;
    return ccNoError;
}

/**
 * cc_msg_
 *
 * Purpose:
 *
 * Return: 
 *
 * Errors: 
 *
 */
cc_int32
cci_msg_calc_magic(void *flat, int flat_len, cc_uint32 * magicp)
{
    cc_uint32 magic = 0;
    int i;
	
    for (i = 0; i < flat_len; i += sizeof(cc_uint32)) {
        magic = magic ^ *(int *)((char *)flat + i);
    }
    *magicp = magic;
    return ccNoError;
}

/**
 * cc_msg_
 *
 * Purpose:
 *
 * Return: 
 *
 * Errors: 
 *
 */
cc_int32 
cci_msg_verify(void *flat, int flat_len, cc_uint32 * validp)  
{
    cc_uint32 *magic1, *magic2;
    cc_uint32 *pheader_len;
    cc_uint32 *ptotal_len;
    cc_uint32 *pblob_len;
    cc_uint32 *ptype;
    cc_uint32 num_blobs = 0;
    cc_uint32 zero = 0;
    cc_uint32 msg_magic, msg_magic2;

    if (flat == NULL || flat_len <= 0 || validp == NULL)
        return ccErrBadParam;

    pheader_len = flat;
    ptotal_len = (cc_uint32 *)((char *)pheader_len + sizeof(cc_uint32));
    ptype = (cc_uint32 *)((char *)ptotal_len + sizeof(cc_uint32));

    if (*ptotal_len != flat_len) {
        *validp = 0;
        return ccNoError;
    }
    
    if (*pheader_len > flat_len) {
        /*too weak. We could verify header_len against type spec header.*/
        *validp = 0;
        return ccNoError;
    }
    if (*ptype > CC_MSG_MAX_TYPE) {
        *validp = 0;
        return ccNoError;
    }

    magic1 = (cc_uint32 *)((char *)ptype + sizeof(cc_uint32) + *pheader_len); 
    if ((char *)magic1 - (char *)flat == (flat_len - 8)) {
        /*There are no data blobs*/
        magic2 = (cc_uint32 *)((char *)magic1 + sizeof(cc_uint32));
        num_blobs = 0;
    } else {
        pblob_len = (cc_uint32 *)((char *)magic1 + sizeof(cc_uint32));
        num_blobs = 1;

        while (*pblob_len + sizeof(cc_uint32) + ((char *)pblob_len - (char *)flat) < (flat_len - sizeof(cc_uint32))) {
            pblob_len = (cc_uint32 *)((char *)pblob_len + *pblob_len + sizeof(cc_uint32));
            num_blobs++;
        }

        if (*pblob_len + sizeof(cc_uint32) + ((char *)pblob_len - (char *)flat) != (flat_len - sizeof(cc_uint32))) {
            /*blobs didn't line up*/
            *validp = 0;
            return ccNoError;
        }
        magic2 = (cc_uint32 *)((char *)pblob_len + *pblob_len + sizeof(cc_uint32)); /*2nd magic should be directly after the last blob*/
    }
	
    if (*magic1 != *magic2) {
        *validp = 0;
        return ccNoError;
    }
    msg_magic = *magic1;

    printf("%d %d\n", (char *)magic1 - (char *)flat, (char *)magic2 - (char *)flat);

    memcpy(magic1, &zero, sizeof(cc_uint32));
    memcpy(magic2, &zero, sizeof(cc_uint32));
    cci_msg_calc_magic(flat, flat_len, &msg_magic2);
    if (msg_magic != msg_magic2) {
        *validp = 0;
        return ccNoError;
    }
    memcpy(magic1, &msg_magic, sizeof(cc_uint32));
    memcpy(magic2, &msg_magic, sizeof(cc_uint32));

    *validp = 1;
    return ccNoError;
}

/**
 * cc_msg_
 *
 * Purpose:
 *
 * Return: 
 *
 * Errors: 
 *
 */
cc_int32
cci_msg_unflatten(void *flat, int flat_len, cc_msg_t** msgpp) 
{
    cc_msg_t* msg;
    char *cur_pos;
    cc_uint32 blob_len;
    char *blob;
    cc_uint32 valid;
    cc_int32 code;

    if ( flat == NULL || flat_len <= 0 || msgpp == NULL )
        return ccErrBadParam;

    code = cci_msg_new(0, &msg);
    if (code)
        return code;

    cci_msg_verify(flat, flat_len, &valid);
    if (valid != 1) {
        cci_msg_destroy(msg);
        return ccErrBadParam;
    }

    cur_pos = flat;
    msg->flat = flat;

    msg->header_len = *(cc_uint32 *)cur_pos;
    cur_pos += sizeof(cc_uint32);

    msg->flat_len = *(cc_uint32 *)cur_pos;
    cur_pos += sizeof(cc_uint32);

    msg->type = *(cc_uint32 *)cur_pos;
    cur_pos += sizeof(cc_uint32);

    msg->header = (void *)malloc(msg->header_len);
    if (msg->header == NULL) {
        cci_msg_destroy(msg);
        return ccErrNoMem;
    }
    memcpy(msg->header, cur_pos, msg->header_len);
    cur_pos += msg->header_len;
	
    msg->magic = *(cc_uint32 *)cur_pos;
    cur_pos += sizeof(cc_uint32);

    if (cur_pos - (char *)flat != flat_len - 8) { /*at least 1 blob*/
        blob_len = *(cc_uint32 *)cur_pos;
        while (blob_len + (cur_pos - (char *)flat) + sizeof(cc_uint32) <= flat_len - sizeof(cc_uint32)) {
            blob = (void *)malloc(blob_len);
            if (blob == NULL) {
                cci_msg_destroy(msg);
                return ccErrNoMem;
            }
            memcpy(blob, cur_pos + sizeof(cc_uint32), blob_len);
            cci_generic_list_append(msg->data_blobs, blob, blob_len, NULL);

            cur_pos += sizeof(cc_uint32) + blob_len;
            blob_len = *(int *)cur_pos;
        }
    }
    *msgpp = msg;
    return ccNoError;
}

cc_int32
cci_msg_retrieve_blob(cc_msg_t* msg, cc_uint32 blob_offset, cc_uint32 blob_len, void **blobp) 
{
    cc_generic_iterate_t*	gen_iterator;
    cc_generic_list_node_t*	gen_node;
    void *ret;
    cc_uint32                   blob_pos;
    cc_int32                    code;

    /*Ensure that the message has been unflattened*/
    if ( msg == NULL || msg->flat == NULL || blob_offset > msg->flat_len || 
         blob_len > msg->flat_len - blob_offset || blobp == NULL)
        return ccErrBadParam;

    code = cci_generic_list_iterator(msg->data_blobs, &gen_iterator);
    while (cci_generic_iterate_has_next(gen_iterator)) {
        code = cci_generic_iterate_next(gen_iterator, &gen_node);
        code = cci_msg_calc_blob_pos(msg, gen_node->data, gen_node->len, &blob_pos);
        if (blob_pos == blob_offset && gen_node->len == blob_len)  {
            free(gen_iterator);
            ret = (void *)malloc(blob_len);
            if (ret == NULL)
                return ccErrNoMem;
            memcpy(ret,(char *)msg->flat + blob_offset, blob_len);	
            *blobp = ret;
            return ccNoError;
        }
    }
    free(gen_iterator);
    return ccIteratorEnd;
}

/**
 * cc_msg_
 *
 * Purpose:
 *
 * Return: 
 *
 * Errors: 
 *
 */
cc_int32 
cci_msg_destroy(cc_msg_t* msg) 
{
    if (msg->flat != NULL) 
        free(msg->flat);
    if (msg->header != NULL)
        free(msg->flat);
    cci_generic_list_destroy(msg->data_blobs);
    free(msg);
    return ccNoError;
}

