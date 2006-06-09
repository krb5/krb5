/*
 * kipc_server.h
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

#ifndef KIPC_SERVER_H
#define KIPC_SERVER_H

#include <Kerberos/kipc_common.h>

#define kKerberosIPCMaxMsgSize               2048 + MAX_TRAILER_SIZE
#define kKerberosIPCTimeout                  200

#if __cplusplus
extern "C" {
#endif
    
typedef kipc_boolean_t (*kipc_demux_proc) (mach_msg_header_t *, mach_msg_header_t *);
    
    
kipc_err_t kipc_server_run_server (kipc_demux_proc in_demux_proc);
    
mach_port_t kipc_server_get_service_port ();
    
kipc_boolean_t kipc_server_quit (void);
    
#if __cplusplus
}
#endif

#endif /* KIPC_SERVER_H */
