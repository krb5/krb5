/*
 * KerberosIPCCommon.h
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

#ifndef KIPC_COMMON_H
#define KIPC_COMMON_H

//#include <Kerberos/KerberosDebug.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <mach/boolean.h>
#include <mach/mach_error.h>
#include <mach/notify.h>
#include <servers/bootstrap.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>


#if __cplusplus
extern "C" {
#endif
    
typedef kern_return_t  kipc_err_t;
typedef boolean_t      kipc_boolean_t;
typedef char          *kipc_string;

#define kkipc_max_message_size  2048 + MAX_TRAILER_SIZE
#define kkipc_timeout           200

// Debugging API used by library
kipc_err_t __kipc_err (kipc_err_t inError, const char *function, const char *file, int line);
#define kipc_err(err) __kipc_err(err, __FUNCTION__, __FILE__, __LINE__)
    
const char *kipc_error_string (kipc_err_t in_error);

kipc_err_t kipc_get_lookup_name (char **out_lookup_name, const char *in_service_id);
kipc_err_t kipc_get_service_name (char **out_service_name, const char *in_service_id);

void kipc_free_string (char *io_string);

#if __cplusplus
}
#endif

#endif /* KIPC_COMMON_H */
