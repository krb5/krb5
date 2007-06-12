/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "ccs_common.h"
#include "cci_array_internal.h"

/* ------------------------------------------------------------------------ */

static cc_int32 ccs_client_object_release (void *io_client)
{
    return cci_check_error (ccs_client_release ((ccs_client_t) io_client));    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_client_array_new (ccs_client_array_t *out_array)
{
    return cci_array_new (out_array, ccs_client_object_release);
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_client_array_release (ccs_client_array_t io_array)
{
    return cci_array_release (io_array);
}

/* ------------------------------------------------------------------------ */

cc_uint64 ccs_client_array_count (ccs_client_array_t in_array)
{
    return cci_array_count (in_array);
}

/* ------------------------------------------------------------------------ */

ccs_client_t ccs_client_array_object_at_index (ccs_client_array_t io_array,
                                               cc_uint64          in_position)
{
    return cci_array_object_at_index (io_array, in_position);
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_client_array_insert (ccs_client_array_t io_array,
                                  ccs_client_t       in_client,
                                  cc_uint64          in_position)
{
    return cci_array_insert (io_array, in_client, in_position);
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_client_array_remove (ccs_client_array_t io_array,
                                  cc_uint64          in_position)
{
    return cci_array_remove (io_array, in_position);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static cc_int32 ccs_lock_object_release (void *io_lock)
{
    return cci_check_error (ccs_lock_release ((ccs_lock_t) io_lock));    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lock_array_new (ccs_lock_array_t *out_array)
{
    return cci_array_new (out_array, ccs_lock_object_release);
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lock_array_release (ccs_lock_array_t io_array)
{
    return cci_array_release (io_array);
}

/* ------------------------------------------------------------------------ */

cc_uint64 ccs_lock_array_count (ccs_lock_array_t in_array)
{
    return cci_array_count (in_array);
}

/* ------------------------------------------------------------------------ */

ccs_lock_t ccs_lock_array_object_at_index (ccs_lock_array_t io_array,
                                           cc_uint64        in_position)
{
    return cci_array_object_at_index (io_array, in_position);
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lock_array_insert (ccs_lock_array_t io_array,
                                ccs_lock_t       in_lock,
                                cc_uint64        in_position)
{
    return cci_array_insert (io_array, in_lock, in_position);
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lock_array_remove (ccs_lock_array_t io_array,
                                cc_uint64        in_position)
{
    return cci_array_remove (io_array, in_position);
}

/* ------------------------------------------------------------------------ */
cc_int32 ccs_lock_array_move (ccs_lock_array_t  io_array,
                              cc_uint64         in_position,
                              cc_uint64         in_new_position,
                              cc_uint64        *out_real_new_position)
{
    return cci_array_move (io_array, in_position, in_new_position, out_real_new_position);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lockref_object_release (void *io_lockref)
{
    return cci_check_error (ccs_lockref_release ((ccs_lockref_t) io_lockref));    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lockref_array_new (ccs_lockref_array_t *out_array)
{
    return cci_array_new (out_array, ccs_lockref_object_release);
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lockref_array_release (ccs_lockref_array_t io_array)
{
    return cci_array_release (io_array);
}

/* ------------------------------------------------------------------------ */

cc_uint64 ccs_lockref_array_count (ccs_lockref_array_t in_array)
{
    return cci_array_count (in_array);
}

/* ------------------------------------------------------------------------ */

ccs_lockref_t ccs_lockref_array_object_at_index (ccs_lockref_array_t io_array,
                                                 cc_uint64           in_position)
{
    return cci_array_object_at_index (io_array, in_position);
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lockref_array_insert (ccs_lockref_array_t io_array,
                                   ccs_lockref_t       in_lockref,
                                   cc_uint64           in_position)
{
    return cci_array_insert (io_array, in_lockref, in_position);
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lockref_array_remove (ccs_lockref_array_t io_array,
                                   cc_uint64           in_position)
{
    return cci_array_remove (io_array, in_position);
}
