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
#include <memory.h>

#include "CredentialsCache.h"
#include "datastore.h"


int main() {
    cc_generic_list_head_t* head;
    cc_generic_list_head_t* copy;// = cc_generic_list_copy(head);
    cc_generic_list_node_t *head_node,*tail,*middle, *node;
    cc_generic_iterate_t* iterate;
    int x1 = 1;
    int x2 = 2;
    int x3 = 3;
    int x4 = 4;
    int x5 = 5;
    int x6 = 6;
    cc_int32 code;

    code = cci_generic_list_new(&head);
    code = cci_generic_list_append(head,&x4,sizeof(x4),NULL);
    code = cci_generic_list_append(head,&x5,sizeof(x5),NULL);
    code = cci_generic_list_append(head,&x6,sizeof(x6),&tail);

    code = cci_generic_list_prepend(head,&x3,sizeof(x3),&middle);
    code = cci_generic_list_prepend(head,&x2,sizeof(x2),NULL);
    code = cci_generic_list_prepend(head,&x1,sizeof(x1), &head_node);

    code = cci_generic_list_iterator(head, &iterate);
    while (cci_generic_iterate_has_next(iterate)) {
        code = cci_generic_iterate_next(iterate, &node);
        printf("%d\n",*((int *)(node->data)));
    }
    printf("----------\n");
    cci_generic_list_remove_element(head,head_node);
    cci_generic_list_remove_element(head,middle);
    cci_generic_list_remove_element(head,tail);

    code = cci_generic_list_iterator(head, &iterate);
    while (cci_generic_iterate_has_next(iterate)) {
        code = cci_generic_iterate_next(iterate, &node);
        printf("%d\n",*((int *)(node->data)));
    }

    printf("----------\n");
    code = cci_generic_list_copy(head, &copy);
    code = cci_generic_list_iterator(copy, &iterate);
    while (cci_generic_iterate_has_next(iterate)) {
        code = cci_generic_iterate_next(iterate, &node);
        printf("%d\n",*((int *)(node->data)));
    }

    cci_generic_list_destroy(copy);
    return 0;
}       
