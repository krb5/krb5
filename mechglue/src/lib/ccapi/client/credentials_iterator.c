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

/* credentials_iterator.c */

#include <stdlib.h>
#include <stdio.h>
#include <CredentialsCache.h>
#include "credentials_iterator.h"
#include "msg.h"
#include "msg_headers.h"


cc_int32
cc_int_credentials_iterator_new( cc_credentials_iterator_t * piter, 
                                 cc_handle ctx,
                                 cc_handle ccache,
                                 cc_handle handle )
{
    cc_int_credentials_iterator_t iter;

    if ( piter == NULL )
        return ccErrBadParam;

    iter = (cc_int_credentials_iterator_t) malloc( sizeof(cc_int_credentials_iterator_d) );
    if ( iter == NULL )
        return ccErrNoMem;

    iter->functions = (cc_credentials_iterator_f*)malloc(sizeof(cc_credentials_iterator_f));
    if ( iter->functions == NULL ) {
        free(iter);
        return ccErrNoMem;
    }

    iter->functions->release = cc_int_credentials_iterator_release;
    iter->functions->next = cc_int_credentials_iterator_next;
    iter->magic = CC_CREDS_ITER_MAGIC;
    iter->ctx = ctx;
    iter->ccache = ccache;
    iter->handle = handle;

    *piter = (cc_credentials_iterator_t) iter;
    return ccNoError;
}

cc_int32
cc_int_credentials_iterator_release( cc_credentials_iterator_t iter )
{
    cc_int_credentials_iterator_t int_iter;
    cc_msg_t        *request;
    ccmsg_creds_iterator_release_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( iter == NULL )
        return ccErrBadParam;

    int_iter = (cc_int_credentials_iterator_t) iter;

    if ( int_iter->magic != CC_CREDS_ITER_MAGIC )
        return ccErrInvalidCredentialsIterator;

    request_header = (ccmsg_creds_iterator_release_t*)malloc(sizeof(ccmsg_creds_iterator_release_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_iter->ctx;
    request_header->ccache = int_iter->ccache;
    request_header->iterator = int_iter->handle;
    code = cci_msg_new(ccmsg_CREDS_ITERATOR_RELEASE, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_creds_iterator_release_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);

    free(int_iter->functions);
    free(int_iter);
    return ccNoError;
}

cc_int32
cc_int_credentials_iterator_next( cc_credentials_iterator_t iter,
                                  cc_credentials_t * credentials )
{
    cc_int_credentials_iterator_t int_iter;
    cc_msg_t        *request;
    ccmsg_creds_iterator_next_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( credentials == NULL )
        return ccErrBadParam;

    int_iter = (cc_int_credentials_iterator_t)iter;

    if ( int_iter->magic != CC_CREDS_ITER_MAGIC )
        return ccErrInvalidCredentialsIterator;

    request_header = (ccmsg_creds_iterator_next_t*)malloc(sizeof(ccmsg_creds_iterator_next_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_iter->ctx;
    request_header->ccache = int_iter->ccache;
    request_header->iterator = int_iter->handle;

    code = cci_msg_new(ccmsg_CREDS_ITERATOR_NEXT, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_creds_iterator_next_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        char * blob;
        ccmsg_creds_iterator_next_resp_t * response_header = (ccmsg_creds_iterator_next_resp_t*)response->header;
        code = cci_msg_retrieve_blob(response, response_header->creds_offset, response_header->creds_len, &blob);
        code = cc_credentials_new(credentials, response_header->version,
                                  int_iter->ctx, int_iter->ccache, response_header->creds_handle, 
                                  blob, response_header->creds_len);
        free(blob);
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}
