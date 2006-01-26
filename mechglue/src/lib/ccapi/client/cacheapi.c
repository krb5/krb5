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

#include <stdlib.h>
#include <stdio.h>
#include <CredentialsCache.h>
#include "ccache.h"
#include "ccache_iterator.h"
#include "context.h"
#include "msg.h"
#include "msg_headers.h"

cc_int32 
cc_initialize (	cc_context_t*		outContext,
                cc_int32		inVersion,
                cc_int32*		outSupportedVersion,
                char const**		outVendor)
{
    static char vendor[128] = "";
    cc_msg_t     *request;
    ccmsg_init_t *request_header;
    cc_msg_t     *response;
    ccmsg_init_resp_t *response_header;
    cc_int32 code;

    if ((inVersion != ccapi_version_2) &&
         (inVersion != ccapi_version_3) &&
         (inVersion != ccapi_version_4) &&
         (inVersion != ccapi_version_5)) {

        if (outSupportedVersion != NULL) {
            *outSupportedVersion = ccapi_version_5;
        }
        return ccErrBadAPIVersion;
    }   

    request_header = (ccmsg_init_t*)malloc(sizeof(ccmsg_init_t));
    if (request_header == NULL)
        return ccErrNoMem;

    request_header->in_version = inVersion;

    code = cci_msg_new(ccmsg_INIT, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_init_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_init_resp_t *)response->header;
        *outSupportedVersion = response_header->out_version;
        code = cc_context_int_new(outContext, response_header->out_ctx, response_header->out_version);

        if (!vendor[0]) {
            char * string;
            code = cci_msg_retrieve_blob(response, response_header->vendor_offset, response_header->vendor_length, &string);
            strncpy(vendor, string, sizeof(vendor)-1);
            vendor[sizeof(vendor)-1] = '\0';
            free(string);
        } 
        *outVendor = vendor;

        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

