/*
 * $Source$
 * $Author$
 *
 *
 * Copyright (c) Hewlett-Packard Company 1991
 * Released to the Massachusetts Institute of Technology for inclusion
 * in the Kerberos source code distribution.
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_create_secure_file
 * krb5_sync_disk_file
 */

#ifdef MODULE_VERSION_ID
static char *VersionID = "@(#)krbfileio.c	2 - 08/22/91";
#endif

#include <krb5/krb5.h>
#include <krb5/libos.h>
#include <krb5/los-proto.h>

#include <sys/file.h>

#include <sys/types.h>
#include <krb5/ext-proto.h>

#ifdef apollo
#   define OPEN_MODE_NOT_TRUSTWORTHY
#endif

krb5_error_code
krb5_create_secure_file(pathname)
    const char * pathname;
{
    int fd;

    /*
     * Create the file with access restricted to the owner
     */
    fd = open(pathname, O_RDWR | O_CREAT | O_EXCL, 0600);

#ifdef OPEN_MODE_NOT_TRUSTWORTHY
    /*
     * Some systems that support default acl inheritance do not 
     * apply ownership information from the process - force the file
     * to have the proper info.
     */
    if (fd > -1) {
        uid_t   uid;
        gid_t   gid;

        uid = getuid();
        gid = getgid();

        fchown(fd, uid, gid);

        fchmod(fd, 0600);
    }
#endif /* OPEN_MODE_NOT_TRUSTWORTHY */

    if (fd > -1) {
        close(fd);
        return 0;
    } else {
        return errno;
    }
}

krb5_error_code
krb5_sync_disk_file(fp)
    FILE *fp;
{
    fflush(fp);
    if (fsync(fileno(fp))) {
        return errno;
    }

    return 0;
}

