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
#include "msg.h"
#include "datastore.h"

#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>

/*testing code*/
int main() 
{
    cc_msg_t* msg;
    double header = 4.05;
    char blob1[] = "This is blob one.1234";
    int blob2 = 2;
    char blob3[] = "This is blob 3.";
    int pos1,pos2,pos3;
    void *flat;
    char *p;
    cc_uint32 valid = 0;
    cc_int32 code;

    code = cci_msg_new(ccmsg_INIT, &msg);
    code = cci_msg_add_header(msg, &header, sizeof(double));
    //cc_msg_add_header(msg, NULL, 0);
    code = cci_msg_add_data_blob(msg, blob1, strlen(blob1) + 1,&pos1);
    code = cci_msg_add_data_blob(msg, &blob2, sizeof(int),&pos2);
    code = cci_msg_add_data_blob(msg, blob3, strlen(blob3) + 1,&pos3);

    cci_msg_flatten(msg,&flat);

    printf("%s\n",(char *)((char *)msg->flat + pos1));
    printf("%d\n",*(int *)((char *)msg->flat + pos2));
    printf("%s\n",(char *)((char *)msg->flat + pos3));

    cci_msg_verify(msg->flat, msg->flat_len, &valid);
    printf("%d\n",valid);

    code = cci_msg_unflatten(msg->flat, msg->flat_len, &msg);

    code = cci_msg_retrieve_blob(msg, pos3, strlen(blob3) + 1, &p);
    printf("%s PPP\n",p);
    return 0;
}
