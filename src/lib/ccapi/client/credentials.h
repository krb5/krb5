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

/* credentials.h */

#define CC_CREDS_MAGIC ('C'<<24 | 'R'<<16 | 'E'<<8 | 'D')

struct cc_int_credentials_d {
    cc_credentials_union* data;
    cc_credentials_f* functions;
#if TARGET_OS_MAC
    cc_credentials_f*     otherFunctions;
#endif
    cc_uint32   magic;
    cc_handle   ctx;
    cc_handle   ccache;
    cc_handle   handle;
};
typedef struct cc_int_credentials_d cc_int_credentials_d;
typedef cc_int_credentials_d* cc_int_credentials_t;

cc_int32
cc_int_credentials_new( cc_credentials_t * pcredentials, cc_uint32 version, 
                    cc_handle ctx, cc_handle ccache, cc_handle handle, 
                    char * data, cc_uint32 len);

cc_int32
cc_int_credentials_release( cc_credentials_t credentials );

cc_int32
cc_int_credentials_compare( cc_credentials_t credentials,
                        cc_credentials_t compare_to,
                        cc_uint32* equal );

cc_int32
cci_creds_v4_marshall( cc_credentials_v4_t * creds, 
                       char ** flat, 
                       cc_uint32 * len);

cc_int32
cci_creds_v5_marshall( cc_credentials_v5_t * creds, 
                       char ** flat, 
                       cc_uint32 * len);

cc_int32
cci_creds_v4_unmarshall( char * flat, 
                             cc_uint32 len,
                             cc_credentials_union * creds);

cc_int32
cci_creds_v5_unmarshall( char * flat, 
                         cc_uint32 len,
                         cc_credentials_union * creds);

