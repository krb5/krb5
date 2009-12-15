/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1996, Massachusetts Institute of Technology.
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
 * Simple test program for testing how GSSAPI import name works.  (May
 * be made into a more full-fledged test program later.)
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>

#define GSSAPI_V2
void display_status (char *, OM_uint32, OM_uint32);
static void display_status_1 (char *, OM_uint32, int);
static void display_buffer (gss_buffer_desc);
static int test_import_name (char *);

FILE *display_file;

int main(argc, argv)
    int argc;
    char **argv;
{
    int retval;

    display_file = stdout;

    retval = test_import_name("host@dcl.mit.edu");

    return retval;
}

static int test_import_name(name)
    char *name;
{
    OM_uint32 maj_stat, min_stat;
    gss_name_t gss_name;
    gss_buffer_desc buffer_name;
    gss_OID name_oid;

    buffer_name.value = name;
    buffer_name.length = strlen(name) + 1;
    maj_stat = gss_import_name(&min_stat, &buffer_name,
                               (gss_OID) gss_nt_service_name,
                               &gss_name);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("parsing name", maj_stat, min_stat);
        return -1;
    }

    maj_stat = gss_display_name(&min_stat, gss_name, &buffer_name,
                                &name_oid);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("displaying context", maj_stat, min_stat);
        return -1;
    }
    printf("name is: ");
    display_buffer(buffer_name);
    printf("\n");
    (void) gss_release_buffer(&min_stat, &buffer_name);

    gss_oid_to_str(&min_stat, name_oid, &buffer_name);
    printf("name type is: ");
    display_buffer(buffer_name);
    printf("\n");
    (void) gss_release_buffer(&min_stat, &buffer_name);
#ifdef  GSSAPI_V2
    (void) gss_release_oid(&min_stat, &name_oid);
#endif
    (void) gss_release_name(&min_stat, &gss_name);
    return 0;
}

static void display_buffer(buffer)
    gss_buffer_desc buffer;
{
    char *namebuf;

    namebuf = malloc(buffer.length+1);
    if (!namebuf) {
        fprintf(stderr, "display_buffer: couldn't allocate buffer!\n");
        exit(1);
    }
    strncpy(namebuf, buffer.value, buffer.length);
    namebuf[buffer.length] = '\0';
    printf("%s", namebuf);
    free(namebuf);
}

void display_status(msg, maj_stat, min_stat)
    char *msg;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
{
    display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
    display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

static void display_status_1(m, code, type)
    char *m;
    OM_uint32 code;
    int type;
{
    OM_uint32 min_stat;
    gss_buffer_desc msg;
#ifdef  GSSAPI_V2
    OM_uint32 msg_ctx;
#else   /* GSSAPI_V2 */
    int msg_ctx;
#endif  /* GSSAPI_V2 */

    msg_ctx = 0;
    while (1) {
        (void) gss_display_status(&min_stat, code,
                                  type, GSS_C_NULL_OID,
                                  &msg_ctx, &msg);
        if (display_file)
            fprintf(display_file, "GSS-API error %s: %s\n", m,
                    (char *)msg.value);
        (void) gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }
}
