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

/* ccache.h */

#define CC_CCACHE_MAGIC ('C'<<24 | 'C'<<16 | 'A'<<8 | 'C')

struct cc_int_ccache_d {
    cc_ccache_f*	functions;
#if TARGET_OS_MAC
    const cc_ccache_f*	otherFunctions;
#endif
    cc_uint32           magic;
    cc_handle           handle;
    cc_handle           ctx;
};
typedef struct cc_int_ccache_d  cc_int_ccache_d;
typedef cc_int_ccache_d*        cc_int_ccache_t;


cc_int32
cc_int_ccache_new( cc_ccache_t * pccache, cc_handle hctx, cc_handle hccache );

cc_int32    
cc_int_ccache_release( cc_ccache_t ccache );

cc_int32    
cc_int_ccache_destroy( cc_ccache_t ccache );

cc_int32
cc_int_ccache_set_default( cc_ccache_t ccache );

cc_int32
cc_int_ccache_get_credentials_version( cc_ccache_t ccache,
                                  cc_uint32* credentials_version);   

cc_int32
cc_int_ccache_get_name( cc_ccache_t ccache,
                   cc_string_t* name );

cc_int32
cc_int_ccache_get_principal( cc_ccache_t ccache,
                        cc_uint32 credentials_version,
                        cc_string_t* principal );

cc_int32
cc_int_ccache_set_principal( cc_ccache_t ccache,
                        cc_uint32 credentials_version,
                        const char* principal );

cc_int32
cc_int_ccache_store_credentials( cc_ccache_t ccache,
                            const cc_credentials_union* credentials );

cc_int32
cc_int_ccache_remove_credentials( cc_ccache_t ccache,
                              cc_credentials_t credentials );

cc_int32
cc_int_ccache_new_credentials_iterator( cc_ccache_t ccache,
                                        cc_credentials_iterator_t* iterator );

cc_int32
cc_int_ccache_move( cc_ccache_t source,
               cc_ccache_t destination );

cc_int32
cc_int_ccache_lock( cc_ccache_t ccache,
               cc_uint32 block,
               cc_uint32 lock_type );

cc_int32
cc_int_ccache_unlock( cc_ccache_t ccache );

cc_int32
cc_int_ccache_get_last_default_time( cc_ccache_t ccache,
                                cc_time_t* time );

cc_int32
cc_int_ccache_get_change_time( cc_ccache_t ccache,
                          cc_time_t* time );

cc_int32
cc_int_ccache_compare( cc_ccache_t ccache,
                  cc_ccache_t compare_to,
                  cc_uint32* equal );

cc_int32	
cc_int_ccache_get_kdc_time_offset( cc_ccache_t ccache,
                              cc_int32	credentials_version,
                              cc_time_t*	time_offset );

cc_int32
cc_int_ccache_set_kdc_time_offset( cc_ccache_t ccache,
                              cc_int32	credentials_version,
                              cc_time_t	time_offset );
                                
cc_int32
cc_int_ccache_clear_kdc_time_offset( cc_ccache_t	ccache,
                                cc_int32	credentials_version );


cc_int32
cc_int_ccache_compat_clone( cc_int_ccache_t     ccache,
                            cc_int_ccache_t    *clone );

