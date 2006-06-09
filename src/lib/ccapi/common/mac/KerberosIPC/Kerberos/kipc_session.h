/*
 * kipc_session.h
 *
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

#ifndef KIPC_SESSION_H
#define KIPC_SESSION_H

#include <Kerberos/kipc_common.h>

#if __cplusplus
extern "C" {
#endif
    
#define kkipc_session_has_gui_access  0x00000001
#define kkipc_session_caller_uses_gui 0x00000002
#define kkipc_session_has_cli_access  0x00000004

typedef u_int32_t kipc_session_attributes_t;
    
    
kipc_boolean_t kipc_session_is_root_session (void);
    
kipc_session_attributes_t kipc_session_get_attributes (void);

kipc_string kipc_get_session_id_string (void);

uid_t kipc_session_get_session_uid (void);
    
uid_t kipc_session_get_server_uid (void);
    
#if __cplusplus
}
#endif

#endif /* KIPC_SESSION_H */
