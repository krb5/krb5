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

/* credentials.c */

#include <stdlib.h>
#include <stdio.h>
#include <CredentialsCache.h>
#include "credentials.h"
#include "msg.h"
#include "msg_headers.h"


cc_int32
cc_int_credentials_new( cc_credentials_t *pcredentials, cc_uint32 version, 
                    cc_handle ctx, cc_handle ccache, cc_handle handle, 
                    char * data, cc_uint32 len )
{
    cc_int_credentials_t credentials;
    cc_int32 code;
    
    if ( pcredentials == NULL )
        return ccErrBadParam;

    credentials = (cc_int_credentials_t)malloc(sizeof(cc_int_credentials_d));
    if ( credentials == NULL )
        return ccErrNoMem;

    credentials->data = (cc_credentials_union *)malloc(sizeof(cc_credentials_union));
    if ( credentials->data == NULL ) {
        free(credentials);
        return ccErrNoMem;
    }

    credentials->functions = (cc_credentials_f *)malloc(sizeof(cc_credentials_f));
    if ( credentials->functions == NULL ) {
        free(credentials->data);
        free(credentials);
        return ccErrNoMem;
    }

    credentials->functions->release = cc_int_credentials_release;
    credentials->functions->compare = cc_int_credentials_compare;
    credentials->magic = CC_CREDS_MAGIC;
    credentials->ctx = ctx;
    credentials->ccache = ccache;
    credentials->handle = handle;

    switch ( version ) {
    case cc_credentials_v4:
        code = cci_cred_v4_unmarshall(data, len, credentials->data);
        break;
    case cc_credentials_v5:
        code = cci_cred_v5_unmarshall(data, len, credentials->data);
        break;
    default:
        free(credentials);
        return ccErrBadCredentialsVersion;
    }

    *pcredentials = (cc_credentials_t)credentials;
    return ccNoError;
}


cc_int32
cc_int_credentials_release( cc_credentials_t creds )
{
    cc_int_credentials_t int_creds;
    unsigned short i;

    if ( creds == NULL )
        return ccErrBadParam;

    int_creds = (cc_int_credentials_t)creds;

    if ( int_creds->magic != CC_CREDS_MAGIC )
        return ccErrInvalidCredentials;

    switch (int_creds->data->version) {
    case cc_credentials_v4:
        free(int_creds->data->credentials.credentials_v4);
        break;
    case cc_credentials_v5:
        if ( int_creds->data->credentials.credentials_v5->client )
            free(int_creds->data->credentials.credentials_v5->client);
        if ( int_creds->data->credentials.credentials_v5->server )
            free(int_creds->data->credentials.credentials_v5->server );
        if ( int_creds->data->credentials.credentials_v5->keyblock.data )
            free(int_creds->data->credentials.credentials_v5->keyblock.data);
        if ( int_creds->data->credentials.credentials_v5->ticket.data )
            free(int_creds->data->credentials.credentials_v5->ticket.data);
        if ( int_creds->data->credentials.credentials_v5->second_ticket.data )
            free(int_creds->data->credentials.credentials_v5->second_ticket.data);
        if ( int_creds->data->credentials.credentials_v5->addresses ) {
            for ( i=0; int_creds->data->credentials.credentials_v5->addresses[i]; i++) {
                if (int_creds->data->credentials.credentials_v5->addresses[i]->data)
                    free(int_creds->data->credentials.credentials_v5->addresses[i]->data);
            }
            free(int_creds->data->credentials.credentials_v5->addresses);
        }
        if ( int_creds->data->credentials.credentials_v5->authdata ) {
            for ( i=0; int_creds->data->credentials.credentials_v5->authdata[i]; i++) {
                if ( int_creds->data->credentials.credentials_v5->authdata[i]->data )
                    free(int_creds->data->credentials.credentials_v5->authdata[i]->data);
            }
            free(int_creds->data->credentials.credentials_v5->authdata);
        }
        break;
    default:
        return ccErrBadCredentialsVersion;
    }

    free(int_creds->functions);
    free(int_creds->data);
    free(int_creds);
    return ccNoError;
}

cc_int32
cc_int_credentials_compare( cc_credentials_t credentials,
                        cc_credentials_t compare_to,
                        cc_uint32* equal )
{
    cc_int_credentials_t int_credentials;
    cc_int_credentials_t int_compare_to;

    if ( credentials == NULL || compare_to == NULL || equal == NULL )
        return ccErrBadParam;

    
    if ( int_credentials->magic != CC_CREDS_MAGIC ||
         int_compare_to->magic != CC_CREDS_MAGIC )
        return ccErrInvalidCredentials;

    int_credentials = (cc_int_credentials_t)credentials;
    int_compare_to  = (cc_int_credentials_t)compare_to;

    *equal = (int_credentials->handle == int_compare_to->handle);
    return ccNoError;
}
