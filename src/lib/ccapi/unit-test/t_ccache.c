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
#include <string.h>
#include <time.h>
#include "CredentialsCache.h"
#include "datastore.h"

int main() {
    cc_server_credentials_t *cred1, *cred2, *cred3;
    cc_credentials_iterate_t* iterator;
    cc_server_credentials_t* stored_cred;
    cc_credentials_list_node_t *node;
    cc_server_ccache_t *c1, *c2;
    char p1[] = "Spike";
    char p2[] = "Jeff";
    int i;
    cc_int32 code;

    code = cci_ccache_new("The first", p1, cc_credentials_v4_v5, &c1);
    code = cci_ccache_new("The 2nd", p2, cc_credentials_v4_v5, &c2);

    cred1 = (cc_server_credentials_t*)malloc(sizeof(cc_server_credentials_t));
    memset(cred1,0,sizeof(cc_server_credentials_t));
    cred2 = (cc_server_credentials_t*)malloc(sizeof(cc_server_credentials_t));
    memset(cred2,0,sizeof(cc_server_credentials_t));
    cred3 = (cc_server_credentials_t*)malloc(sizeof(cc_server_credentials_t));
    memset(cred3,0,sizeof(cc_server_credentials_t));

    cred1->creds.version = cred2->creds.version = cc_credentials_v4;
    cred3->creds.version = cc_credentials_v5;

    cred1->creds.credentials.credentials_v4 = (cc_credentials_v4_t*)malloc(sizeof(cc_credentials_v4_t));
    memset(cred1->creds.credentials.credentials_v4,0,sizeof(cc_credentials_v4_t));
    cred2->creds.credentials.credentials_v4 = (cc_credentials_v4_t*)malloc(sizeof(cc_credentials_v4_t));
    memset(cred2->creds.credentials.credentials_v4,0,sizeof(cc_credentials_v4_t));
    cred3->creds.credentials.credentials_v5 = (cc_credentials_v5_t*)malloc(sizeof(cc_credentials_v5_t));
    memset(cred3->creds.credentials.credentials_v5,0,sizeof(cc_credentials_v5_t));

    strncpy(cred1->creds.credentials.credentials_v4->principal, p1, strlen(p1));
    strncpy(cred2->creds.credentials.credentials_v4->principal, p1, strlen(p1));
    cred3->creds.credentials.credentials_v5->client = p1;

    code = cci_ccache_store_creds(c1, &cred1->creds);
    printf("(c1, cred1) -> %d\n",code);

    code = cci_ccache_store_creds(c1, &cred2->creds);
    printf("(c1, cred2) -> %d\n",code);

    code = cci_ccache_store_creds(c2, &cred3->creds);
    printf("(c2, cred3) -> %d\n",code);

    code = cci_ccache_store_creds(c1, &cred3->creds);
    printf("(c1, cred3) -> %d\n",code);

    i = 0;
    code = cci_ccache_move(c1, c2);
    code = cci_ccache_destroy(c1);
    code = cci_ccache_new_iterator(c2, &iterator);
    while (cci_credentials_iterate_has_next(iterator)) {
        i++;
        code = cci_credentials_iterate_next(iterator, &node);
        stored_cred = (cc_server_credentials_t *)node->data;
        printf("%d %d %s\n", stored_cred->is_default, stored_cred->creds.version, stored_cred->creds.credentials.credentials_v4->principal);

        if (i == 1) {
            code = cci_ccache_rem_creds(c2,&cred2->creds);
            printf("(c2 rem cred2) -> %d\n",code);
        }
    }
    return 0;
}

