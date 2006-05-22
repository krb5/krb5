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

#include <stdlib.h>
#include <stdio.h>
#include <CredentialsCache.h>
#include "ccache.h"
#include "ccache_iterator.h"
#include "context.h"
#include "cc_rpc.h"
#include "msg.h"
#include "msg_headers.h"

/*! \fn cc_initialize
 *  \brief A function that initializes a ccapi context for the caller.
 *  \param[out] outContext a cc_context_t pointer to which is assigned the newly created context upon success.
 *  \param[in]  inVersion  a cc_int32 that specifies the 
 */

CCACHE_API cc_int32 
cc_initialize (	cc_context_t*		outContext,
                cc_int32		inVersion,
                cc_int32*		outSupportedVersion,
                char const**		outVendor)
{
    static char vendor[128] = "";
    cc_msg_t     *request;
    ccmsg_init_t *request_header;
    cc_msg_t     *response;
    cc_uint32 type;
    ccmsg_init_resp_t *response_header;
    cc_int32 code;

    if ((inVersion != ccapi_version_2) &&
         (inVersion != ccapi_version_3) &&
         (inVersion != ccapi_version_4) &&
         (inVersion != ccapi_version_5) &&
	 (inVersion != ccapi_version_6)) {

        if (outSupportedVersion != NULL) {
            *outSupportedVersion = ccapi_version_6;
        }
        return ccErrBadAPIVersion;
    }   

    request_header = (ccmsg_init_t*)malloc(sizeof(ccmsg_init_t));
    if (request_header == NULL)
        return ccErrNoMem;

    /* If the version number is 2, the caller will be passing
     * the structure into the v2 compatibility functions which
     * in turn will call the v6 functions.  Set the version to
     * ccapi_version_max since that is what the compatibility 
     * functions will be expecting.
     */
    if (inVersion == ccapi_version_2)
	inVersion = ccapi_version_max;

    /* Construct the request */
    request_header->in_version = htonl(inVersion);

    code = cci_msg_new(ccmsg_INIT, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_init_t));

    code = cci_perform_rpc(request, &response);

    type = ntohl(response->type);
    if (type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = ntohl(nack_header->err_code);
    } else if (type == ccmsg_ACK) {
        response_header = (ccmsg_init_resp_t *)response->header;
        *outSupportedVersion = ntohl(response_header->out_version);
        code = cc_int_context_new(outContext, ntohll(response_header->out_ctx), ntohl(response_header->out_version));

        if (!vendor[0]) {
            char * string;
            code = cci_msg_retrieve_blob(response, ntohl(response_header->vendor_offset), ntohl(response_header->vendor_length), &string);
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

