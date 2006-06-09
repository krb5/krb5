/* $Copyright:
 *
 * Copyright 2004-2006 by the Massachusetts Institute of Technology.
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
#include <string.h>
#include <CredentialsCache.h>
#include "msg.h"
#include "msg_headers.h"
#include "marshall.h"

cc_int32
cci_creds_v4_marshall( cc_credentials_v4_t * creds, 
                       char ** pflat, 
                       cc_uint32 * plen)
{
    cc_uint32 len;
    char * flat;
    cci_flat_creds_v4_t * header;
    cc_time64 t64;

    if ( creds == NULL || pflat == NULL || plen == NULL )
        return ccErrBadParam;

    len = sizeof(cci_flat_creds_v4_t);
    flat = (char *)malloc(len);
    if ( flat == NULL )
        return ccErrNoMem;
    memset(flat, 0, len);

    header = (cci_flat_creds_v4_t *)flat;
    header->version = htonl(creds->version);
    memcpy(header->principal, creds->principal, cc_v4_name_size);
    memcpy(header->principal_instance, creds->principal_instance, cc_v4_instance_size);
    memcpy(header->service, creds->service, cc_v4_name_size);
    memcpy(header->service_instance, creds->service_instance, cc_v4_instance_size);
    memcpy(header->realm, creds->realm, cc_v4_realm_size);
    memcpy(header->session_key, creds->session_key, cc_v4_key_size);
    header->kvno = htonl(creds->kvno);
    header->string_to_key_type = htonl(creds->string_to_key_type);
    t64 = creds->issue_date;
    header->issue_date = htonll(t64);
    header->lifetime = htonl(creds->lifetime);
    /* TODO: verify that address is stored in host order */
    header->address = htonl(creds->address);
    header->ticket_size = htonl(creds->ticket_size);
    memcpy(header->ticket, creds->ticket, cc_v4_ticket_size);

    *pflat = flat;
    *plen = len;

    return ccNoError;	
}

cc_int32
cci_creds_v4_unmarshall( char * flat, 
                         cc_uint32 len,
                         cc_credentials_union * creds_union)
{
    struct cci_flat_creds_v4 * header;
    cc_credentials_v4_t * creds;
    cc_time64 t64;

    if ( flat == NULL || len == 0 || creds_union == NULL )
        return ccErrBadParam;

    creds_union->version = cc_credentials_v4;

    header = (cci_flat_creds_v4_t *)flat;

    creds = (cc_credentials_v4_t *)malloc(sizeof(cc_credentials_v4_t));
    if ( creds == NULL )
	return ccErrNoMem;

    creds->version = ntohl(header->version);
    memcpy(creds->principal, header->principal, cc_v4_name_size);
    memcpy(creds->principal_instance, header->principal_instance, cc_v4_instance_size);
    memcpy(creds->service, header->service, cc_v4_name_size);
    memcpy(creds->service_instance, header->service_instance, cc_v4_instance_size);
    memcpy(creds->realm, header->realm, cc_v4_realm_size);
    memcpy(creds->session_key, header->session_key, cc_v4_key_size);
    creds->kvno = htonl(header->kvno);
    creds->string_to_key_type = htonl(header->string_to_key_type);
    t64 = header->issue_date;
    creds->issue_date = (cc_time64)ntohll(t64);
    creds->lifetime = (cc_int32)ntohl(header->lifetime);
    /* TODO: verify that address is stored in host order */
    creds->address = ntohl(header->address);
    creds->ticket_size = ntohl(header->ticket_size);
    memcpy(creds->ticket, header->ticket, cc_v4_ticket_size);

    creds_union->credentials.credentials_v4 = creds;

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
    cc_uint32 length;
    cc_uint32 offset;
    cc_time64 t64;
    cc_uint32 count;
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
    header->version = htonl(FLAT_CREDS_V5_VERSION);
    if (creds->client) {
	length = strlen(creds->client) + 1;
        header->client.length = htonl(length);
        header->client.data = htonl(offset);
        memcpy(flat + offset, creds->client, length);
        offset += length;
    }

    if (creds->server) {
	length = strlen(creds->server) + 1;
        header->server.length = htonl(length);
        header->server.data = htonl(offset);
        memcpy(flat + offset, creds->server, length);
        offset += length;
    }

    header->keyblock.type = htonl(creds->keyblock.type);
    if (creds->keyblock.length) {
	length = creds->keyblock.length;
        header->keyblock.length = htonl(length);
        header->keyblock.data = htonl(offset);
        memcpy(flat + offset, creds->keyblock.data, length);
        offset += length;
    }           

    t64 = creds->authtime;
    header->authtime = htonll(t64);
    t64 = creds->starttime;
    header->starttime = htonll(t64);
    t64 = creds->endtime;
    header->endtime = htonll(t64);
    t64 = creds->renew_till;
    header->renew_till = htonll(t64);

    header->is_skey = htonl(creds->is_skey);
    header->ticket_flags = htonl(creds->ticket_flags);

    cci_creds_cc_data_array_count_entries( creds->addresses, &count );
    if ( count ) {
        cc_flat_data * addresses = (cc_flat_data *)flat + offset;
	header->address_count = htonl(count);
        header->addresses = htonl(offset);
        offset += count * sizeof(cc_flat_data);

        for ( i=0; i < count; i++ ) {
            addresses[i].type = htonl(creds->addresses[i]->type);
            if (creds->addresses[i]->length) {
		length = creds->addresses[i]->length;
                addresses[i].length = htonl(length);
                addresses[i].data = htonl(offset);
		/* TODO: verify that addresses are stored in network order */
                memcpy(flat + offset, creds->addresses[i]->data, length);
                offset += length;
            }
        }
    }

    header->ticket.type = htonl(creds->ticket.type);
    if (creds->ticket.length) {
	length = creds->ticket.length;
        header->ticket.length = htonl(length);
        header->ticket.data = htonl(offset);
        memcpy(flat + offset, creds->ticket.data, length);
        offset += length;
    }           

    header->second_ticket.type = htonl(creds->second_ticket.type);
    if (creds->second_ticket.length) {
	length = creds->second_ticket.length;
        header->second_ticket.length = htonl(length);
        header->second_ticket.data = htonl(offset);
        memcpy(flat + offset, creds->second_ticket.data, length);
        offset += length;
    }           

    cci_creds_cc_data_array_count_entries( creds->authdata, &count );
    if ( count ) {
        cc_flat_data * authdata = (cc_flat_data *)flat + offset;

	header->authdata_count = htonl(count);
        header->authdata = (offset);
        offset += count * sizeof(cc_flat_data);

        for ( i=0; i < count; i++ ) {
            authdata[i].type = htonl(creds->authdata[i]->type);
            if (creds->authdata[i]->length) {
		length = creds->authdata[i]->length;
                authdata[i].length = htonl(length);
                authdata[i].data = htonl(offset);
                memcpy(flat + offset, creds->authdata[i]->data, length);
                offset += length;
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
    cc_time64 t64;
    cc_uint32  length;
    cc_uint32  count;
    cc_uint32  i;

    if ( flat == NULL || len == 0 || creds_union == NULL )
        return ccErrBadParam;

    creds_union->version = cc_credentials_v5;

    header = (struct cci_flat_creds_v5 *)flat;

    if ( ntohl(header->version) != FLAT_CREDS_V5_VERSION )
        return ccErrBadParam;

    creds = (cc_credentials_v5_t *)malloc(sizeof(cc_credentials_v5_t));
    if ( creds == NULL )
        return ccErrNoMem;
    memset(creds, 0, sizeof(cc_credentials_v5_t));

    if ( header->client.length ) {
	length = ntohl(header->client.length);
        creds->client = (char *)malloc(length);
        memcpy(creds->client, flat + header->client.data, length);
    }

    if ( header->server.length ) {
	length = ntohl(header->server.length);
        creds->server = (char *)malloc(length);
        memcpy(creds->server, flat + header->server.data, length);
    }

    creds->keyblock.type = ntohl(header->keyblock.type);
    if ( header->keyblock.length ) {
	length = ntohl(header->keyblock.length);
        creds->keyblock.length = length;
        creds->keyblock.data = malloc(length);
        memcpy(creds->keyblock.data, flat + header->keyblock.data, length);
    }

    /* TODO: need to perform overflow validation checks to ensure
     * that we do not attempt to store too large a value into cc_time_t
     * when it is a 32-bit field.
     */
    t64 = ntohll(header->authtime);
    creds->authtime = (cc_time)t64;
    t64 = ntohll(header->starttime);
    creds->starttime = (cc_time)t64;
    t64 = ntohll(header->endtime);
    creds->endtime = (cc_time)t64;
    t64 = ntohll(header->renew_till);
    creds->renew_till = (cc_time)t64;

    creds->is_skey = ntohl(header->is_skey);
    creds->ticket_flags = ntohl(header->ticket_flags);

    count = ntohl(header->address_count);
    creds->addresses = (cc_data **) malloc((count + 1) * sizeof(cc_data *));
    flat_data = (cc_flat_data *)flat + header->addresses;
    for ( i=0 ; i < count ; i++ ) {
        creds->addresses[i] = (cc_data *)malloc(sizeof(cc_data));
        creds->addresses[i]->type = ntohl(flat_data[i].type);
	length = ntohl(flat_data[i].length);
        creds->addresses[i]->length = length;
        if ( length ) {
            creds->addresses[i]->data = malloc(length);
	    /* TODO: verify that addresses are stored in network order */
            memcpy(creds->addresses[i]->data, flat + flat_data[i].data, length);
        } else {
            creds->addresses[i]->data = NULL;
        }
    }
    creds->addresses[i] = NULL;

    creds->ticket.type = ntohl(header->ticket.type);
    length = ntohl(header->ticket.length);
    if ( length ) {
        creds->ticket.length = length;
        creds->ticket.data = malloc(length);
        memcpy(creds->ticket.data, flat + header->ticket.data, length);
    }

    creds->second_ticket.type = header->second_ticket.type;
    if ( header->second_ticket.length ) {
        creds->second_ticket.length = header->second_ticket.length;
        creds->second_ticket.data = malloc(creds->second_ticket.length);
        memcpy(creds->second_ticket.data, flat + header->second_ticket.data, creds->second_ticket.length);
    }

    count = ntohl(header->authdata_count);
    creds->authdata = (cc_data **) malloc((count + 1) * sizeof(cc_data *));
    flat_data = (cc_flat_data *)flat + header->authdata;
    for ( i=0 ; i < count ; i++ ) {
        creds->authdata[i] = (cc_data *)malloc(sizeof(cc_data));
        creds->authdata[i]->type = ntohl(flat_data[i].type);
	length = ntohl(flat_data[i].length);
        creds->authdata[i]->length = length;
        if ( length ) {
            creds->authdata[i]->data = malloc(length);
            memcpy(creds->authdata[i]->data, flat + flat_data[i].data, length);
        } else {
            creds->authdata[i]->data = NULL;
        }
    }
    creds->authdata[i] = NULL;

    creds_union->credentials.credentials_v5 = creds;

    return ccNoError;
}

