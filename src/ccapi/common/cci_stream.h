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

#ifndef CCI_STREAM_H
#define CCI_STREAM_H

#include "cci_types.h"

cc_int32 cci_stream_new (cci_stream_t *out_stream);

cc_uint32 cci_stream_release (cci_stream_t io_stream);

inline cc_uint64 cci_stream_size (cci_stream_t in_stream);

inline const char *cci_stream_data (cci_stream_t in_stream);

cc_uint32 cci_stream_read (cci_stream_t  in_stream, 
                           void         *io_data,
                           cc_uint64     in_size);
cc_uint32 cci_stream_write (cci_stream_t  in_stream, 
                            const void   *in_data,
                            cc_uint64     in_size);

cc_uint32 cci_stream_read_string (cci_stream_t   io_stream, 
                                  char         **out_string);
cc_uint32 cci_stream_write_string (cci_stream_t  io_stream, 
                                   const char   *in_string);

cc_uint32 cci_stream_read_int32 (cci_stream_t  io_stream, 
                                 cc_int32     *out_int32);
cc_uint32 cci_stream_write_int32 (cci_stream_t io_stream, 
                                  cc_int32     in_int32);

cc_uint32 cci_stream_read_uint32 (cci_stream_t  io_stream, 
                                  cc_uint32    *out_uint32);
cc_uint32 cci_stream_write_uint32 (cci_stream_t io_stream, 
                                   cc_uint32    in_uint32);

cc_uint32 cci_stream_read_int64 (cci_stream_t  io_stream, 
                                 cc_int64     *out_int64);
cc_uint32 cci_stream_write_int64 (cci_stream_t io_stream, 
                                  cc_int64     in_int64);

cc_uint32 cci_stream_read_uint64 (cci_stream_t  io_stream, 
                                  cc_uint64    *out_uint64);
cc_uint32 cci_stream_write_uint64 (cci_stream_t io_stream, 
                                   cc_uint64    in_uint64);

cc_uint32 cci_stream_read_time (cci_stream_t  io_stream, 
                                cc_time_t    *out_time);
cc_uint32 cci_stream_write_time (cci_stream_t io_stream, 
                                 cc_time_t    in_time);

#endif /* CCI_STREAM_H */
