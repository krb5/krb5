/*
 * kipc_session.c
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

#include <Security/AuthSession.h>
#include <pwd.h>
#include <Kerberos/kipc_session.h>

// ---------------------------------------------------------------------------

kipc_boolean_t kipc_session_is_root_session (void)
{
    kipc_err_t           err = 0;
    kipc_boolean_t       is_root_session = TRUE;  // safer to assume root session
    SessionAttributeBits sattrs = 0L;    
    
    err = SessionGetInfo (callerSecuritySession, NULL, &sattrs);
    
    if (!err) {
        is_root_session = (sattrs & sessionIsRoot);
        dprintf ("%s(): running in %s session", 
                 __FUNCTION__, is_root_session ? "the root" : "a user");
    } else {
        dprintf ("%s(): SessionGetInfo() failed with %d", __FUNCTION__, err);
    }
    
    return is_root_session;
}

// ---------------------------------------------------------------------------

kipc_session_attributes_t kipc_session_get_attributes (void)
{
    kipc_session_attributes_t attributes = 0L;
    SessionAttributeBits      sattrs = 0L;    
    int                       fd_stdin = fileno (stdin);
    int                       fd_stdout = fileno (stdout);
    char                     *fd_stdin_name = ttyname (fd_stdin);
    
    if ((SessionGetInfo (callerSecuritySession, NULL, &sattrs) == noErr) && (sattrs & sessionHasGraphicAccess)) {
        dprintf ("%s(): Session has graphic access.", __FUNCTION__);
        attributes |= kkipc_session_has_gui_access;
        
        // Check for the HIToolbox (Carbon) or AppKit (Cocoa).  If either is loaded, we are a GUI app!
        CFBundleRef hiToolBoxBundle = CFBundleGetBundleWithIdentifier (CFSTR ("com.apple.HIToolbox"));
        if (hiToolBoxBundle != NULL && CFBundleIsExecutableLoaded (hiToolBoxBundle)) {
            dprintf ("%s(): Carbon Toolbox is loaded.", __FUNCTION__);
            attributes |= kkipc_session_caller_uses_gui;
        }
        
        CFBundleRef appKitBundle = CFBundleGetBundleWithIdentifier (CFSTR ("com.apple.AppKit"));
        if (appKitBundle != NULL && CFBundleIsExecutableLoaded (appKitBundle)) {
            dprintf ("%s(): AppKit is loaded.", __FUNCTION__);
            attributes |= kkipc_session_caller_uses_gui;
        }
    }
    
    // Session info isn't reliable for remote sessions.
    // Check manually for terminal access with file descriptors
    if (isatty (fd_stdin) && isatty (fd_stdout) && (fd_stdin_name != NULL)) {
        dprintf ("%s(): Terminal '%s' of type '%s' exists.", 
                 __FUNCTION__, fd_stdin_name, getenv ("TERM"));
        attributes |= kkipc_session_has_cli_access;
    }
    
    dprintf ("%s(): Attributes are %x", __FUNCTION__, attributes);
    return attributes;
}

// ---------------------------------------------------------------------------

kipc_string kipc_get_session_id_string (void)
{
    // Session ID is a 32 bit quanitity, so the longest string is 0xFFFFFFFF
    static char          s_session_name[16];
    SecuritySessionId    id;
    
    s_session_name[0] = '\0';
    
    if (SessionGetInfo (callerSecuritySession, &id, NULL) == noErr) {
        snprintf (s_session_name, sizeof (s_session_name), "0x%lx", id);
    }
    
    return s_session_name;
}

// ---------------------------------------------------------------------------

uid_t kipc_session_get_session_uid (void)
{
    // Get the uid of the user that the server will be run and named for.
    uid_t uid = geteuid ();
    
    // Avoid root because the client can later go back to the real uid    
    if (uid == 0 /* root */) {
        dprintf ("%s(): geteuid returned UID %d, trying getuid...\n", __FUNCTION__, uid);
        uid = getuid ();
    }
    
    return uid;
}

// ---------------------------------------------------------------------------

uid_t kipc_session_get_server_uid (void)
{
    uid_t server_uid = 92;
    
    struct passwd *pw = getpwnam ("securityagent");
    if (pw != NULL) {
        server_uid = pw->pw_uid;
    } else {
        dprintf ("%s: getpwnam(securityagent) failed, using hardcoded value.", __FUNCTION__);
    }
    
    return server_uid;
}
