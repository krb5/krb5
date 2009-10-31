/*
 * Copyright 2008 Massachusetts Institute of Technology.
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

#import "k5_mig_requestServer.h"
#import "k5_mig_reply.h"
#import "k5-ipc_stream.h"
#import "k5_mig_server.h"


int32_t kim_agent_listen_loop (void);

int32_t kim_handle_reply_init (mach_port_t   in_reply_port,
                               int32_t       in_error);

int32_t kim_handle_reply_enter_identity (mach_port_t   in_reply_port,
                                         kim_identity  in_identity,
                                         kim_options   in_options,
                                         kim_boolean   in_change_password,
                                         int32_t       in_error);

int32_t kim_handle_reply_select_identity (mach_port_t   in_reply_port,
                                          kim_identity  in_identity,
                                          kim_options   in_options,
                                          kim_boolean   in_change_password,
                                          int32_t       in_error);

int32_t kim_handle_reply_auth_prompt (mach_port_t   in_reply_port,
                                      kim_string    in_prompt_response,
                                      kim_boolean   in_allow_save_response,
                                      int32_t       in_error);

int32_t kim_handle_reply_change_password (mach_port_t   in_reply_port,
                                          kim_string    in_old_password,
                                          kim_string    in_new_password,
                                          kim_string    in_vfy_password,
                                          int32_t       in_error);

int32_t kim_handle_reply_handle_error (mach_port_t   in_reply_port,
                                       int32_t       in_error);

int32_t kim_handle_reply_fini (mach_port_t   in_reply_port,
                               int32_t       in_error);
