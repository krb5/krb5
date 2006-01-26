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

/* marshall.c */

#include <stdlib.h>
#include <stdio.h>
#include <CredentialsCache.h>
#include "msg.h"
#include "msg_headers.h"
#include "marshall.h"

cc_int32
cci_creds_v4_marshall( cc_credentials_v4_t * creds, 
                       char ** flat, 
                       cc_uint32 * len)
{
    cc_msg_t *  msg;
    ccmsg_creds_v4_t * header;
    cc_uint32   blob_pos;
    cc_int32    code;

    if ( creds == NULL || flat == NULL || len == NULL )
        return ccErrBadParam;

    header = (ccmsg_creds_v4_t *)malloc(sizeof(ccmsg_creds_v4_t));
    if ( header == NULL )
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CREDS_V4, &msg);

    code = cci_msg_add_header(msg, header, sizeof(ccmsg_creds_v4_t));

    code = cci_msg_add_data_blob(msg, creds, sizeof(cc_credentials_v4_t), &blob_pos);

    header->offset = blob_pos;
    header->len    = sizeof(cc_credentials_v4_t);

    code = cci_msg_flatten( msg, NULL );

    *flat = msg->flat;
    *len  = msg->flat_len;
    msg->flat = NULL;
    msg->flat_len = 0;

    cci_msg_destroy(msg);

    return ccNoError;
}

cc_int32
cci_creds_v4_unmarshall( char * flat, 
                         cc_uint32 len,
                         cc_credentials_union * creds)
{
    cc_msg_t * msg; 
    ccmsg_creds_v4_t * header;
    cc_int32   code;

    if ( flat == NULL || len == 0 || creds == NULL )
        return ccErrBadParam;

    code = cci_msg_unflatten( flat, len, &msg );

    header = (ccmsg_creds_v4_t *)msg->header;

    creds->version = cc_credentials_v4;
    code = cci_msg_retrieve_blob(msg, header->offset, header->len, &creds->credentials.credentials_v4);

    cci_msg_destroy(msg);

    return ccNoError;
}


cc_int32
cci_creds_cc_data_array_count_entries( cc_data ** array, cc_uint32 * pcount)
{
    cc_uint32 count;

    if (array == NULL) {
        *pcount = 0;
        return ccNoError;
    }

    for ( count=0; array[count] != NULL ; count++) ;

    *pcount = count;
    return ccNoError;
}

cc_int32
cci_creds_v5_compute_flat_size( cc_credentials_v5_t * creds, cc_uint32 * plen)
{
    cc_uint32 len;
    cc_uint32 i, count;

    len = sizeof(struct cci_flat_creds_v5);

    if (creds->client)
        len += strlen(creds->client) + 1;

    if (creds->server)
        len += strlen(creds->server) + 1;

    len += creds->keyblock.length;

    cci_creds_cc_data_array_count_entries( creds->addresses, &count );
    len += count * sizeof(cc_flat_data);
    for ( i=0; i<count; i++ ) {
        len += creds->addresses[i]->length;
    }

    len += creds->ticket.length;
    len += creds->second_ticket.length;

    cci_creds_cc_data_array_count_entries( creds->authdata, &count );
    len += count * sizeof(cc_flat_data);
    for ( i=0; i<count; i++ ) {
        len += creds->authdata[i]->length;
    }

    *plen = len;
    return ccNoError;
}

cc_int32
cci_creds_v5_marshall( cc_credentials_v5_t * creds, 
                       char ** pflat, 
                       cc_uint32 * plen)
{
    cc_uint32 len;
    char * flat;
    struct cci_flat_creds_v5 * header;
    cc_uint32 offset;
    cc_uint32 i;

    if ( creds == NULL || pflat == NULL || plen == NULL )
        return ccErrBadParam;

    cci_creds_v5_compute_flat_size(creds, &len);

    flat = (char *)malloc(len);
    if ( flat == NULL )
        return ccErrNoMem;
    memset(flat, 0, len);

    offset = sizeof(struct cci_flat_creds_v5);
    header = (struct cci_flat_creds_v5 *)flat;
    header->version = FLAT_CREDS_V5_VERSION;
    if (creds->client) {
        header->client.length = strlen(creds->client) + 1;
        header->client.data = offset;
        memcpy(flat + offset, creds->client, header->client.length);
        offset += header->client.length;
    }

    if (creds->server) {
        header->server.length = strlen(creds->server) + 1;
        header->server.data = offset;
        memcpy(flat + offset, creds->server, header->server.length);
        offset += header->server.length;
    }

    header->keyblock.type = creds->keyblock.type;
    if (creds->keyblock.length) {
        header->keyblock.length = creds->keyblock.length;
        header->keyblock.data = offset;
        memcpy(flat + offset, creds->keyblock.data, header->keyblock.length);
        offset += header->keyblock.length;
    }           

    header->authtime = creds->authtime;
    header->starttime = creds->starttime;
    header->endtime = creds->endtime;
    header->renew_till = creds->renew_till;
    header->is_skey = creds->is_skey;
    header->ticket_flags = creds->ticket_flags;

    cci_creds_cc_data_array_count_entries( creds->addresses, &header->address_count );
    if ( header->address_count ) {
        cc_flat_data * addresses = (cc_flat_data *)flat + offset;
        header->addresses = offset;
        offset += header->address_count * sizeof(cc_flat_data);

        for ( i=0; i<header->address_count; i++ ) {
            addresses[i].type = creds->addresses[i]->type;
            if (creds->addresses[i]->length) {
                addresses[i].length = creds->addresses[i]->length;
                addresses[i].data = offset;
                memcpy(flat + offset, creds->addresses[i]->data, addresses[i].length);
                offset += addresses[i].length;
            }
        }
    }

    header->ticket.type = creds->ticket.type;
    if (creds->ticket.length) {
        header->ticket.length = creds->ticket.length;
        header->ticket.data = offset;
        memcpy(flat + offset, creds->ticket.data, header->ticket.length);
        offset += header->ticket.length;
    }           

    header->second_ticket.type = creds->second_ticket.type;
    if (creds->second_ticket.length) {
        header->second_ticket.length = creds->second_ticket.length;
        header->second_ticket.data = offset;
        memcpy(flat + offset, creds->second_ticket.data, header->second_ticket.length);
        offset += header->second_ticket.length;
    }           

    cci_creds_cc_data_array_count_entries( creds->authdata, &header->authdata_count );
    if ( header->authdata_count ) {
        cc_flat_data * authdata = (cc_flat_data *)flat + offset;
        header->authdata = offset;
        offset += header->authdata_count * sizeof(cc_flat_data);

        for ( i=0; i<header->authdata_count; i++ ) {
            authdata[i].type = creds->authdata[i]->type;
            if (creds->authdata[i]->length) {
                authdata[i].length = creds->authdata[i]->length;
                authdata[i].data = offset;
                memcpy(flat + offset, creds->authdata[i]->data, authdata[i].length);
                offset += authdata[i].length;
            }
        }
    }

    *pflat = flat;
    *plen = len;
    return ccNoError;
}


// TODO: a much better job of checking for out of memory errors
//       and validating that we do not read beyond the flat input
//       data buffer

cc_int32
cci_creds_v5_unmarshall( char * flat, 
                         cc_uint32 len,
                         cc_credentials_union * creds_union)
{
    struct cci_flat_creds_v5 * header;
    cc_credentials_v5_t * creds;
    cc_flat_data * flat_data;
    cc_uint32  i;
    cc_int32   code;

    if ( flat == NULL || len == 0 || creds_union == NULL )
        return ccErrBadParam;

    creds_union->version = cc_credentials_v5;

    header = (struct cci_flat_creds_v5 *)flat;

    if ( header->version != FLAT_CREDS_V5_VERSION )
        return ccErrBadParam;

    creds = (cc_credentials_v5_t *)malloc(sizeof(cc_credentials_v5_t));
    if ( creds == NULL )
        return ccErrNoMem;
    memset(creds, 0, sizeof(ccmsg_creds_v5_t));

    if ( header->client.length ) {
        creds->client = (char *)malloc(header->client.length);
        memcpy(creds->client, flat + header->client.data, header->client.length);
    }

    if ( header->server.length ) {
        creds->server = (char *)malloc(header->server.length);
        memcpy(creds->server, flat + header->server.data, header->server.length);
    }

    creds->keyblock.type = header->keyblock.type;
    if ( header->keyblock.length ) {
        creds->keyblock.length = header->keyblock.length;
        creds->keyblock.data = malloc(creds->keyblock.length);
        memcpy(creds->keyblock.data, flat + header->keyblock.data, creds->keyblock.length);
    }

    creds->authtime = header->authtime;
    creds->starttime = header->starttime;
    creds->endtime = header->endtime;
    creds->renew_till = header->renew_till;
    creds->is_skey = header->is_skey;
    creds->ticket_flags = header->ticket_flags;

    creds->addresses = (cc_data **) malloc((header->address_count + 1) * sizeof(cc_data *));
    flat_data = (cc_flat_data *)flat + header->addresses;
    for ( i=0 ; i < header->address_count ; i++ ) {
        creds->addresses[i] = (cc_data *)malloc(sizeof(cc_data));
        creds->addresses[i]->type = flat_data[i].type;
        creds->addresses[i]->length = flat_data[i].length;
        if ( flat_data[i].length ) {
            creds->addresses[i]->data = malloc(flat_data[i].length);
            memcpy(creds->addresses[i]->data, flat + flat_data[i].data, flat_data[i].length);
        } else {
            creds->addresses[i]->data = NULL;
        }
    }
    creds->addresses[i] = NULL;

    creds->ticket.type = header->ticket.type;
    if ( header->ticket.length ) {
        creds->ticket.length = header->ticket.length;
        creds->ticket.data = malloc(creds->ticket.length);
        memcpy(creds->ticket.data, flat + header->ticket.data, creds->ticket.length);
    }

    creds->second_ticket.type = header->second_ticket.type;
    if ( header->second_ticket.length ) {
        creds->second_ticket.length = header->second_ticket.length;
        creds->second_ticket.data = malloc(creds->second_ticket.length);
        memcpy(creds->second_ticket.data, flat + header->second_ticket.data, creds->second_ticket.length);
    }

    creds->authdata = (cc_data **) malloc((header->authdata_count + 1) * sizeof(cc_data *));
    flat_data = (cc_flat_data *)flat + header->authdata;
    for ( i=0 ; i < header->authdata_count ; i++ ) {
        creds->authdata[i] = (cc_data *)malloc(sizeof(cc_data));
        creds->authdata[i]->type = flat_data[i].type;
        creds->authdata[i]->length = flat_data[i].length;
        if ( flat_data[i].length ) {
            creds->authdata[i]->data = malloc(flat_data[i].length);
            memcpy(creds->authdata[i]->data, flat + flat_data[i].data, flat_data[i].length);
        } else {
            creds->authdata[i]->data = NULL;
        }
    }
    creds->authdata[i] = NULL;

    creds_union->credentials.credentials_v5 = creds;

    return ccNoError;
}

