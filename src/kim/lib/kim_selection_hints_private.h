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

#ifndef KIM_SELECTION_HINTS_PRIVATE_H
#define KIM_SELECTION_HINTS_PRIVATE_H

#include <kim/kim.h>
#include "k5-ipc_stream.h"

typedef struct kim_selection_hints_preference_strings {
    kim_string application_identifier;
    kim_string service_identity;
    kim_string client_realm;
    kim_string user;
    kim_string service_realm;
    kim_string service;
    kim_string server;
} kim_selection_hints_preference_strings;

kim_error kim_selection_hints_get_application_id (kim_selection_hints  in_selection_hints,
                                                  kim_string          *out_application_id);

kim_error kim_selection_hints_get_preference_strings (kim_selection_hints                     in_selection_hints,
                                                      kim_selection_hints_preference_strings *io_preference_strings);

kim_error kim_os_selection_hints_lookup_identity (kim_selection_hints  in_selection_hints,
                                                  kim_identity        *out_identity);

kim_error kim_os_selection_hints_remember_identity (kim_selection_hints in_selection_hints,
                                                    kim_identity        in_identity);

kim_error kim_os_selection_hints_forget_identity (kim_selection_hints in_selection_hints);

kim_error kim_selection_hints_write_to_stream (kim_selection_hints in_selection_hints,
                                               k5_ipc_stream       io_stream);

kim_error kim_selection_hints_read_from_stream (kim_selection_hints io_selection_hints,
                                                k5_ipc_stream       io_stream);

kim_error kim_selection_hints_create_from_stream (kim_selection_hints *out_selection_hints,
                                                  k5_ipc_stream        in_stream);

#endif /* KIM_SELECTION_HINTS_PRIVATE_H */
