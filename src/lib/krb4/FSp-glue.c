/*
 * lib/krb4/FSp-glue.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2002 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
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
 * MacOS-specific glue for using FSSpecs to deal with srvtabs.
 */

#include "krb.h"
#include "krb4int.h"
#include <stdio.h>
#include <string.h>

#if TARGET_OS_MAC && defined(__FILES__)

#include <CoreServices/CoreServices.h>

static int FSp_srvtab_to_key(char *, char *, char *, char *, C_Block);
static OSStatus FSSpec2Path (FSSpec *spec, char **path, int pathLen);

int KRB5_CALLCONV
FSp_read_service_key(
    char *service,              /* Service Name */
    char *instance,             /* Instance name or "*" */
    char *realm,                /* Realm */
    int kvno,                   /* Key version number */
    const FSSpec *filespec,     /* Filespec */
    char *key)                  /* Pointer to key to be filled in */
{
    int retval = KFAILURE;
    char file [MAXPATHLEN];
    if (filespec != NULL) {
        if (FSSpec2Path (filespec, &file, sizeof(file)) != noErr) {
            return retval;
        }
    }
    retval = read_service_key(service, instance, realm, kvno, file, key);
    if (file != NULL) {
        free (file);
    }
    return retval;
}

int KRB5_CALLCONV
FSp_put_svc_key(
    const FSSpec *sfilespec,
    char *name,
    char *inst,
    char *realm,
    int newvno,
    char *key)
{
    int retval = KFAILURE;
    char sfile[MAXPATHLEN];

    if (sfilespec != NULL) {
        if (FSSpec2Path (sfilespec, &sfile, sizeof(sfile)) != noErr) {
            return retval;
        }
    }
    retval = put_svc_key(sfile, name, inst, realm, newvno, key);
    if (sfile != NULL) {
        free (sfile);
    }
    return retval;
}

int KRB5_CALLCONV
FSp_krb_get_svc_in_tkt(
    char *user, char *instance, char *realm, 
    char *service, char *sinstance, int life,
    const FSSpec *srvtab)
{
    /* Cast the FSSpec into the password field.  It will be pulled out again */
    /* by FSp_srvtab_to_key and used to read the real password */
    return krb_get_in_tkt(user, instance, realm, service, sinstance,
                          life, FSp_srvtab_to_key, NULL, (char *)srvtab);
}

static int FSp_srvtab_to_key(char *user, char *instance, char *realm, 
			     char *srvtab, C_Block key)
{
    /* FSp_read_service_key correctly handles a NULL FSSpecPtr */
    return FSp_read_service_key(user, instance, realm, 0,
				(FSSpec *)srvtab, (char *)key);
}

static OSStatus FSSpec2Path (FSSpec *spec, char **path, int pathLen)
{
    OSStatus err = noErr;
    FSRef ref;
    
    /* check parameters */
    if (path == NULL) err = paramErr;
    
    /* convert the FSSpec to an FSRef */
    if (err == noErr) {
        FSRefParam pb;
        
        pb.ioVRefNum = spec->vRefNum;
        pb.ioDirID = spec->parID;
        pb.ioNamePtr = (StringPtr) spec->name;
        pb.newRef = &ref;
        err = PBMakeFSRefSync(&pb);
    }
    
    /* and then convert the FSRef to a path */
    if (err == noErr) {
        err = FSRefMakePath (&ref, path, pathLen);
    }
    
    return err;
}

#endif
