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

#ifndef KIM_IDENTITY_PRIVATE_H
#define KIM_IDENTITY_PRIVATE_H

#include <kim/kim.h>
#include "kim_library_private.h"
#include "kim_ui_private.h"

krb5_principal kim_identity_krb5_principal (kim_identity in_identity);

kim_error kim_identity_is_tgt_service (kim_identity  in_identity,
                                       kim_boolean  *out_is_tgt_service);


kim_error kim_os_identity_create_for_username (kim_identity *out_identity);


kim_boolean kim_os_identity_allow_save_password (void);

kim_error kim_os_identity_get_saved_password (kim_identity  in_identity,
                                              kim_string   *out_password);

kim_error kim_os_identity_set_saved_password (kim_identity in_identity,
                                              kim_string   in_password);

kim_error kim_os_identity_remove_saved_password (kim_identity in_identity);

kim_error kim_identity_change_password_with_credential (kim_identity    in_identity,
                                                        kim_credential  in_credential,
                                                        kim_string      in_new_password,
                                                        kim_ui_context *in_ui_context,
                                                        kim_error      *out_rejected_err,
                                                        kim_string     *out_rejected_message,
                                                        kim_string     *out_rejected_description);

kim_error kim_identity_change_password_common (kim_identity    in_identity,
                                               kim_boolean     in_old_password_expired,
                                               kim_ui_context *in_ui_context,
                                               kim_string     *out_new_password);

#endif /* KIM_IDENTITY_PRIVATE_H */
