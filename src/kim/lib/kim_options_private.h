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

#ifndef KIM_OPTIONS_PRIVATE_H
#define KIM_OPTIONS_PRIVATE_H

#include <kim/kim.h>
#include "k5-ipc_stream.h"

kim_error kim_options_create_empty (kim_options *out_options);

krb5_get_init_creds_opt *kim_options_init_cred_options (kim_options in_options);

char *kim_options_service_name (kim_options in_options);

kim_time kim_options_start_time (kim_options in_options);


kim_error kim_options_write_to_stream (kim_options   in_options,
                                       k5_ipc_stream io_stream);

kim_error kim_options_read_from_stream (kim_options    io_options,
                                        k5_ipc_stream  io_stream);

kim_error kim_options_create_from_stream (kim_options   *out_options,
                                          k5_ipc_stream  io_stream);

#endif /* KIM_OPTIONS_PRIVATE_H */
