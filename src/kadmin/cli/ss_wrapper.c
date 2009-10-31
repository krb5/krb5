/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1994 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
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
 *
 *
 * ss wrapper for kadmin
 */

#include <krb5.h>
#include <ss/ss.h>
#include <stdio.h>
#include <string.h>
#include "kadmin.h"

extern ss_request_table kadmin_cmds;
extern int exit_status;
extern char *whoami;

int
main(int argc, char *argv[])
{
    char *request;
    krb5_error_code retval;
    int sci_idx, code = 0;

    whoami = ((whoami = strrchr(argv[0], '/')) ? whoami+1 : argv[0]);

    request = kadmin_startup(argc, argv);
    sci_idx = ss_create_invocation(whoami, "5.0", NULL, &kadmin_cmds, &retval);
    if (retval) {
        ss_perror(sci_idx, retval, "creating invocation");
        exit(1);
    }
    if (request) {
        code = ss_execute_line(sci_idx, request);
        if (code != 0) {
            ss_perror(sci_idx, code, request);
            exit_status++;
        }
    } else
        retval = ss_listen(sci_idx);
    return quit() ? 1 : exit_status;
}
