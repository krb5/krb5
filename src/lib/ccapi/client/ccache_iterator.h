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

/* ccache_iterator.h */

#define CC_CCACHE_ITER_MAGIC ('C'<<24 | 'C'<<16 | 'I'<<8 | 'T')

struct cc_int_ccache_iterator_d {
    cc_ccache_iterator_f*	functions;
#if TARGET_OS_MAC
    cc_ccache_iterator_f*	otherFunctions;
#endif
    cc_uint32           magic;
    cc_handle           handle;
    cc_handle           ctx;

    cc_uint32           repeat_count;
    cc_ccache_t         compat_copy;
};
typedef struct cc_int_ccache_iterator_d cc_int_ccache_iterator_d;
typedef cc_int_ccache_iterator_d*	cc_int_ccache_iterator_t;


cc_int32
cc_int_ccache_iterator_new( cc_ccache_iterator_t * piter,
                            cc_handle ctx,
                            cc_handle handle );

cc_int32
cc_int_ccache_iterator_release( cc_ccache_iterator_t iter );

cc_int32
cc_int_ccache_iterator_next( cc_ccache_iterator_t iter,
                             cc_ccache_t * ccache );

cc_int32
cc_int_ccache_iterator_set_repeat_count( cc_int_ccache_iterator_t iter, 
                                         cc_uint32 count );

cc_int32
cc_int_ccache_iterator_get_repeat_count( cc_int_ccache_iterator_t iter, 
                                         cc_uint32 * count );



