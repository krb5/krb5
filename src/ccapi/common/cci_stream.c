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

#include "cci_common.h"

#if TARGET_OS_MAC 
#include <architecture/byte_order.h>

#if !defined(htonll)
#define htonll(x) OSSwapHostToBigInt64(x)
#endif

#if !defined(ntohll)
#define ntohll(x) OSSwapBigToHostInt64(x)
#endif

#endif /* TARGET_OS_MAC */

struct cci_stream_d {
    char *data;
    cc_uint64 size;
    cc_uint64 max_size;
};

const struct cci_stream_d cci_stream_initializer = { NULL, 0, 0 };

#define CC_STREAM_SIZE_INCREMENT 128

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_stream_reallocate (cci_stream_t io_stream,
                                        cc_uint64    in_new_size)
{
    cc_int32 err = ccNoError;
    cc_uint64 new_max_size = 0;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        cc_uint64 old_max_size = io_stream->max_size;
        new_max_size = io_stream->max_size;
        
        if (in_new_size > old_max_size) {
            /* Expand the stream */
            while (in_new_size > new_max_size) {
                new_max_size += CC_STREAM_SIZE_INCREMENT;
            }
            
        
        } else if ((in_new_size + CC_STREAM_SIZE_INCREMENT) < old_max_size) {
            /* Shrink the array, but never drop below CC_LIST_COUNT_INCREMENT */
            while ((in_new_size + CC_STREAM_SIZE_INCREMENT) < new_max_size &&
                   (new_max_size > CC_STREAM_SIZE_INCREMENT)) {
                new_max_size -= CC_STREAM_SIZE_INCREMENT;
            }
        }
    }
    
    if (!err && new_max_size != io_stream->max_size) {
        char *data = io_stream->data;
 
        if (!data) {
            data = malloc (new_max_size * sizeof (*data));
        } else {
            data = realloc (data, new_max_size * sizeof (*data));
        }
        
        if (data) { 
            io_stream->data = data;
            io_stream->max_size = new_max_size;
        } else {
            err = cci_check_error (ccErrNoMem); 
        }
    }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 cci_stream_new (cci_stream_t *out_stream)
{
    cc_int32 err = ccNoError;
    cci_stream_t stream = NULL;
    
    if (!out_stream) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        stream = malloc (sizeof (*stream));
        if (stream) { 
            *stream = cci_stream_initializer;
        } else {
            err = cci_check_error (ccErrNoMem); 
        }
    }
    
    if (!err) {
        *out_stream = stream;
        stream = NULL;
    }
    
    cci_stream_release (stream);
    
    return cci_check_error (err);    
}


/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_release (cci_stream_t io_stream)
{	
    cc_int32 err = ccNoError;
    
    if (!io_stream) { err = ccErrBadParam; }
    
    if (!err) {
        free (io_stream->data);
        free (io_stream);
    }
    
    return err;    
}

/* ------------------------------------------------------------------------ */

inline cc_uint64 cci_stream_size (cci_stream_t in_stream)
{
    return in_stream ? in_stream->size : 0;
}


/* ------------------------------------------------------------------------ */

inline const char *cci_stream_data (cci_stream_t in_stream)
{
    return in_stream ? in_stream->data : NULL;
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_read (cci_stream_t  io_stream, 
                           void         *io_data, 
                           cc_uint64     in_size)
{
    cc_int32 err = ccNoError;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!io_data  ) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        if (in_size > io_stream->size) { 
            err = cci_check_error (ccErrBadInternalMessage); 
        }
    }
    
    if (!err) {
        memcpy (io_data, io_stream->data, in_size);
        memmove (io_stream->data, &io_stream->data[in_size], 
                 io_stream->size - in_size);
        
        err = cci_stream_reallocate (io_stream, io_stream->size - in_size);
        
        if (!err) {
            io_stream->size -= in_size;
        }
    }
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_write (cci_stream_t  io_stream,
                            const void   *in_data, 
                            cc_uint64     in_size)
{
    cc_int32 err = ccNoError;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!in_data  ) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        /* Security check: Do not let the caller overflow the length */
        if (in_size > (UINT64_MAX - io_stream->size)) {
            err = cci_check_error (ccErrBadParam);
        }
    }
    
    if (!err) {
        err = cci_stream_reallocate (io_stream, io_stream->size + in_size);
    }
    
    if (!err) {
        memcpy (&io_stream->data[io_stream->size], in_data, in_size);
        io_stream->size += in_size;
    }
    
    return cci_check_error (err);
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_read_string (cci_stream_t   io_stream, 
                                  char         **out_string)
{
    cc_int32 err = ccNoError;
    cc_uint32 length = 0;
    char *string = NULL;
    
    if (!io_stream ) { err = cci_check_error (ccErrBadParam); }
    if (!out_string) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_read_uint32 (io_stream, &length);
    }
    
    if (!err) {
        string = malloc (length);
        if (!string) { err = cci_check_error (ccErrNoMem); }
    }
    
    if (!err) {
        err = cci_stream_read (io_stream, string, length);
    }
    
    if (!err) {
        *out_string = string;
        string = NULL;
    }
    
    free (string);

    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_write_string (cci_stream_t  io_stream, 
                                   const char   *in_string)
{
    cc_int32 err = ccNoError;
    cc_uint32 length = 0;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!in_string) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        length = strlen (in_string) + 1;
        
        err = cci_stream_write_uint32 (io_stream, length);
    }
    
    if (!err) {
        err = cci_stream_write (io_stream, in_string, length);
    }
    
    return cci_check_error (err);
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_read_int32 (cci_stream_t  io_stream, 
                                 cc_int32     *out_int32)
{
    cc_int32 err = ccNoError;
    cc_int32 int32 = 0;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!out_int32) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_read (io_stream, &int32, sizeof (int32));
    }
    
    if (!err) {
        *out_int32 = ntohl (int32);
    }
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_write_int32 (cci_stream_t io_stream, 
                                  cc_int32     in_int32)
{
    cc_int32 err = ccNoError;
    cc_int32 int32 = htonl (in_int32);
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_write (io_stream, &int32, sizeof (int32));
    }
    
    return cci_check_error (err);
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_read_uint32 (cci_stream_t  io_stream, 
                                  cc_uint32    *out_uint32)
{
    cc_int32 err = ccNoError;
    cc_uint32 uint32 = 0;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!out_uint32) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_read (io_stream, &uint32, sizeof (uint32));
    }
    
    if (!err) {
        *out_uint32 = ntohl (uint32);
    }
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_write_uint32 (cci_stream_t io_stream, 
                                   cc_uint32    in_uint32)
{
    cc_int32 err = ccNoError;
    cc_int32 uint32 = htonl (in_uint32);
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_write (io_stream, &uint32, sizeof (uint32));
    }
    
    return cci_check_error (err);
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_read_int64 (cci_stream_t  io_stream, 
                                 cc_int64     *out_int64)
{
    cc_int32 err = ccNoError;
    cc_uint64 int64 = 0;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!out_int64) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_read (io_stream, &int64, sizeof (int64));
    }
    
    if (!err) {
        *out_int64 = ntohll (int64);
    }
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_write_int64 (cci_stream_t io_stream, 
                                  cc_int64     in_int64)
{
    cc_int32 err = ccNoError;
    cc_int64 int64 = htonll (in_int64);
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_write (io_stream, &int64, sizeof (int64));
    }
    
    return cci_check_error (err);
}


#pragma mark - 

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_read_uint64 (cci_stream_t  io_stream, 
                                  cc_uint64     *out_uint64)
{
    cc_int32 err = ccNoError;
    cc_uint64 uint64 = 0;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!out_uint64) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_read (io_stream, &uint64, sizeof (uint64));
    }
    
    if (!err) {
        *out_uint64 = ntohll (uint64);
    }
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_write_uint64 (cci_stream_t io_stream, 
                                   cc_uint64     in_uint64)
{
    cc_int32 err = ccNoError;
    cc_int64 uint64 = htonll (in_uint64);
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_write (io_stream, &uint64, sizeof (uint64));
    }
    
    return cci_check_error (err);
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_read_time (cci_stream_t  io_stream, 
                                cc_time_t    *out_time)
{
    cc_int32 err = ccNoError;
    cc_int64 t = 0;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!out_time ) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_read_int64 (io_stream, &t);
    }
    
    if (!err) {
        *out_time = t;
    }
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

cc_uint32 cci_stream_write_time (cci_stream_t io_stream, 
                                 cc_time_t    in_time)
{
    cc_int32 err = ccNoError;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_write_int64 (io_stream, in_time);
    }
    
    return cci_check_error (err);
}
