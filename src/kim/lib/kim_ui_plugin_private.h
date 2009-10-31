/*
 * $Header$
 *
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

#ifndef KIM_UI_PLUGIN_PRIVATE_H
#define KIM_UI_PLUGIN_PRIVATE_H

#include <kim/kim.h>

struct kim_ui_plugin_context;
typedef struct kim_ui_plugin_context *kim_ui_plugin_context;


kim_error kim_ui_plugin_init (kim_ui_context *io_context);

kim_error kim_ui_plugin_enter_identity (kim_ui_context *in_context,
                                        kim_options     io_options,
                                        kim_identity   *out_identity,
                                        kim_boolean    *out_change_password);

kim_error kim_ui_plugin_select_identity (kim_ui_context      *in_context,
                                         kim_selection_hints  io_hints,
                                         kim_identity        *out_identity,
                                         kim_boolean         *out_change_password);

kim_error kim_ui_plugin_auth_prompt (kim_ui_context      *in_context,
                                     kim_identity         in_identity,
                                     kim_prompt_type      in_type,
                                     kim_boolean          in_allow_save_reply,
                                     kim_boolean          in_hide_reply,
                                     kim_string           in_title,
                                     kim_string           in_message,
                                     kim_string           in_description,
                                     char               **out_reply,
                                     kim_boolean         *out_save_reply);

kim_error kim_ui_plugin_change_password (kim_ui_context  *in_context,
                                         kim_identity     in_identity,
                                         kim_boolean      in_old_password_expired,
                                         char           **out_old_password,
                                         char           **out_new_password,
                                         char           **out_verify_password);

kim_error kim_ui_plugin_handle_error (kim_ui_context *in_context,
                                      kim_identity    in_identity,
                                      kim_error       in_error,
                                      kim_string      in_error_message,
                                      kim_string      in_error_description);

void kim_ui_plugin_free_string (kim_ui_context  *in_context,
                                char           **io_string);

kim_error kim_ui_plugin_fini (kim_ui_context *in_context);

#endif /* KIM_UI_PLUGIN_PRIVATE_H */
