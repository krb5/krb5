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

/* context.h */

#define CC_CONTEXT_MAGIC ('C'<<24 | 'C'<<16 | 'T'<<8 | 'X')

struct cc_int_context {
    cc_context_f*	functions;

    cc_uint32           magic;
#ifdef CCAPI_V2_COMPAT
    cc_uint32           version;
#endif
    cc_uint32           api_version;
    cc_handle           handle;
};
typedef struct cc_int_context cc_int_context_d;
typedef cc_int_context_d*     cc_int_context_t;

cc_int32
cc_int_context_new( cc_context_t *pcontext, cc_handle handle, cc_uint32 version );

cc_int32    
cc_int_context_release( cc_context_t context );

cc_int32
cc_int_context_get_change_time( cc_context_t context,
                                cc_time_t* time);

cc_int32
cc_int_context_get_default_ccache_name( cc_context_t context,
                                        cc_string_t* name );

cc_int32
cc_int_context_open_ccache( cc_context_t context,
                            const char* name,
                            cc_ccache_t* ccache );

cc_int32
cc_int_context_open_default_ccache( cc_context_t context,
                                    cc_ccache_t* ccache );

cc_int32
cc_int_context_create_ccache( cc_context_t context,
                              const char* name,
                              cc_uint32 cred_vers,
                              const char* principal, 
                              cc_ccache_t* ccache );

cc_int32
cc_int_context_create_default_ccache( cc_context_t context,
                                      cc_uint32 cred_vers,
                                      const char* principal, 
                                      cc_ccache_t* ccache );

cc_int32
cc_int_context_create_new_ccache( cc_context_t context,
                                  cc_uint32 cred_vers,
                                  const char* principal, 
                                  cc_ccache_t* ccache );
 
cc_int32
cc_int_context_new_ccache_iterator( cc_context_t context,
                                    cc_ccache_iterator_t* iterator );

cc_int32
cc_int_context_lock( cc_context_t context,
                     cc_uint32 lock_type,
                     cc_uint32 block );

cc_int32
cc_int_context_unlock( cc_context_t context );

cc_int32
cc_int_context_compare( cc_context_t context,
                        cc_context_t compare_to,
                        cc_uint32*   equal );

cc_int32
cc_int_context_clone( cc_context_t      inContext,
                      cc_context_t*     outContext,
                      cc_int32          requestedVersion,
                      cc_int32*         supportedVersion,
                      char const**      vendor );

cc_int32
cc_int_context_get_version( cc_context_t        context,
                            cc_int32*           version );


