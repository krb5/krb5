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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "CredentialsCache.h"
#include "datastore.h"


/*testing code*/
int main() {
    int uid = 1;
    int session = 1;
    cc_server_ccache_t *ccache;
    cc_credentials_union* creds;
    cc_ccache_iterate_t* ccache_iterator;
    cc_ccache_list_node_t* ccache_node;
    cc_credentials_iterate_t* creds_iterator;
    cc_credentials_list_node_t* creds_node;
    cc_server_credentials_t* server_creds;
    cc_auth_info_t* auth_info = NULL;
    cc_session_info_t* session_info = NULL;
    cc_server_context_t* ctx = NULL;
    char *name;
    int i;
    cc_int32 code;

    code = cci_context_new(5, auth_info, session_info, &ctx);
    code = cci_context_create_default_ccache(ctx, cc_credentials_v4, "Spike", &ccache);
    code = cci_context_get_default_ccache_name(ctx, &name);
    code = cci_context_open_ccache(ctx, name, &ccache);
	
    for (i = 0; i < 5; i++) {
        creds = (cc_credentials_union*)malloc(sizeof(cc_credentials_union));
        creds->version = cc_credentials_v4;
        creds->credentials.credentials_v4 = (cc_credentials_v4_t*)malloc(sizeof(cc_credentials_v4_t));
        strcpy(creds->credentials.credentials_v4->principal, "Spike");

        code = cci_ccache_store_creds(ccache, creds);
    }

    code = cci_context_create_ccache(ctx, "ccache 2", cc_credentials_v4, "Jeff", &ccache);
    code = cci_context_open_ccache(ctx, "ccache 2", &ccache);
	
    for (i = 0; i < 5; i++) {
        creds = (cc_credentials_union*)malloc(sizeof(cc_credentials_union));
        creds->version = cc_credentials_v4;
        creds->credentials.credentials_v4 = (cc_credentials_v4_t*)malloc(sizeof(cc_credentials_v4_t));
        strcpy(creds->credentials.credentials_v4->principal, "Jeff");

        cci_ccache_store_creds(ccache, creds);
    }

    code = cci_context_ccache_iterator(ctx, &ccache_iterator);
    while (cci_ccache_iterate_has_next(ccache_iterator)) {
        code = cci_ccache_iterate_next(ccache_iterator, &ccache_node);
        ccache = (cc_server_ccache_t *)ccache_node->data;
        printf("%x for %s %s default = %d v %d\n",
               ccache, ccache->principal_v4, ccache->principal_v5, 
               ccache->is_default, ccache->versions);

        code = cci_ccache_new_iterator(ccache, &creds_iterator);
        while (cci_credentials_iterate_has_next(creds_iterator)) {
            code = cci_credentials_iterate_next(creds_iterator, &creds_node);
            server_creds = (cc_server_credentials_t *)creds_node->data;	
            printf("\t%s %d\n", 
                   server_creds->creds.credentials.credentials_v4->principal, 
                   creds->version);
        }
    }       
    return 0;
}
