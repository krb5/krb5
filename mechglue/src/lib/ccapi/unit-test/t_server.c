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


#include "CredentialsCache.h"
#include "serv_ops.h"
#include "datastore.h"
#include "rpc_auth.h"
#include "msg_headers.h"

#include <stdlib.h>

static int 
read_flat_msg(char ** flat_msg, cc_uint32 * flat_len)
{               
    
    /* TODO - read length of message */
    *flat_len = 999;

    *flat_msg = (char *)malloc(*flat_len);

    /* TODO - read message into buffer */

    return 0;
}

static int
send_flat_msg(char * flag_msg, cc_uint32 flat_len)
{
        
    return 0;
}

static int 
obtain_auth_info(cc_auth_info_t ** auth)
{
    if (auth == NULL)
        return ccErrBadParam;

    *auth = malloc(sizeof(cc_auth_info_t));
    if (auth == NULL)
        return ccErrNoMem;
    
    memset(*auth,0,sizeof(cc_auth_info_t));

    /* TODO: obtain real auth data from connection */

    return ccNoError;
}

static int
destroy_auth_info(cc_auth_info_t * auth)
{
    if (auth == NULL)
        return ccErrBadParam;

    if (auth->info)
        free(auth->info);

    free(auth);

    return ccNoError;
}

static int 
obtain_session_info(cc_session_info_t ** session)
{
    if (session == NULL)
        return ccErrBadParam;

    *session = malloc(sizeof(cc_session_info_t));
    if (session == NULL)
        return ccErrNoMem;
    
    memset(*session,0,sizeof(cc_session_info_t));

    /* TODO: obtain real session data from connection */

    return ccNoError;
}

static int
destroy_session_info(cc_session_info_t * session)
{
    if (session == NULL)
        return ccErrBadParam;

    if (session->info)
        free(session->info);

    free(session);

    return ccNoError;
}


int
main(void)
{
    cc_msg_t *          msg;
    cc_msg_t *          resp;
    cc_auth_info_t    * auth_info;
    cc_session_info_t * session_info;
    cc_int32            code;

    if ( cci_serv_initialize() != ccNoError )
        return 1;

    while ( 1 ) {
        msg = (cc_msg_t *)malloc(sizeof(cc_msg_t));

        /* read message */
        if (read_flat_msg(&msg->flat, &msg->flat_len))
            continue;

        /* unflatten message */
        code = cci_msg_unflatten(msg->flat, msg->flat_len, &msg); 

        /* obtain auth info */
        code = obtain_auth_info(&auth_info);

        /* obtain session info */
        code = obtain_session_info(&session_info);

        /* process message */
        code = cci_serv_process_msg(msg, auth_info, session_info, &resp);

        /* flatten response */
        code = cci_msg_flatten(resp, NULL);

        /* send response */
        code = send_flat_msg(resp->flat, resp->flat_len);

        code = destroy_auth_info(auth_info);

        code = destroy_session_info(session_info);

        /* free message */
        code = cci_msg_destroy(msg);

        /* free response */
        code = cci_msg_destroy(resp);
    }
    return 0;
}
