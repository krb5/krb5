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

#include <pwd.h>
#include <unistd.h>
#include <Security/Security.h>

#include "kim_os_private.h"

/* ------------------------------------------------------------------------ */

kim_boolean kim_os_identity_allow_save_password (void)
{
    kim_boolean disabled = 0;
    CFPropertyListRef disable_pref = NULL;

    disable_pref = CFPreferencesCopyValue (CFSTR ("SavePasswordDisabled"),
                                           KIM_PREFERENCES_FILE,
                                           kCFPreferencesAnyUser,
                                           kCFPreferencesAnyHost);
    if (!disable_pref) {
        disable_pref = CFPreferencesCopyValue (CFSTR ("SavePasswordDisabled"),
                                               KIM_PREFERENCES_FILE,
                                               kCFPreferencesAnyUser,
                                               kCFPreferencesCurrentHost);
    }

    if (!disable_pref) {
        disable_pref = CFPreferencesCopyValue (CFSTR ("SavePasswordDisabled"),
                                               KA_PREFERENCES_FILE,
                                               kCFPreferencesAnyUser,
                                               kCFPreferencesAnyHost);
    }

    if (!disable_pref) {
        disable_pref = CFPreferencesCopyValue (CFSTR ("SavePasswordDisabled"),
                                               KA_PREFERENCES_FILE,
                                               kCFPreferencesAnyUser,
                                               kCFPreferencesCurrentHost);
    }

    disabled = (disable_pref &&
                CFGetTypeID (disable_pref) == CFBooleanGetTypeID () &&
                CFBooleanGetValue (disable_pref));

    if (disable_pref) { CFRelease (disable_pref); }

    return !disabled;
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_identity_get_saved_password (kim_identity  in_identity,
                                              kim_string   *out_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_string realm = NULL;
    kim_string name = NULL;
    void *buffer = NULL;
    UInt32 length = 0;

    if (!err && !in_identity ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err && !kim_library_allow_home_directory_access ()) {
        err = check_error (ENOENT); /* simulate no password found */
    }

    if (!err && !kim_os_identity_allow_save_password ()) {
        err = kim_os_identity_remove_saved_password (in_identity);
        if (!err) {
            err = check_error (ENOENT); /* simulate no password found */
        }
    }

    if (!err) {
        err = kim_identity_get_components_string (in_identity, &name);
    }

    if (!err) {
        err = kim_identity_get_realm (in_identity, &realm);
    }

    if (!err) {
        err = SecKeychainFindGenericPassword (nil,
                                              strlen (realm), realm,
                                              strlen (name), name,
                                              &length, &buffer,
                                              nil);

        if (!err && !buffer) { err = check_error (ENOENT); }
    }

    if (!err) {
        err = kim_string_create_from_buffer (out_password, buffer, length);
    }

    kim_string_free (&name);
    kim_string_free (&realm);
    if (buffer) { SecKeychainItemFreeContent (NULL, buffer); }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_identity_set_saved_password (kim_identity in_identity,
                                              kim_string   in_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_string realm = NULL;
    kim_string name = NULL;

    if (!err && !in_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err && !kim_library_allow_home_directory_access ()) {
        return KIM_NO_ERROR; /* simulate no error */
    }

    if (!err && !kim_os_identity_allow_save_password ()) {
        return kim_os_identity_remove_saved_password (in_identity);
    }

    if (!err) {
        err = kim_identity_get_components_string (in_identity, &name);
    }

    if (!err) {
        err = kim_identity_get_realm (in_identity, &realm);
    }

    if (!err) {
        SecKeychainItemRef itemRef = NULL;
        UInt32 namelen = strlen (name);
        UInt32 realmlen = strlen (realm);

        /* Add the password to the keychain */
        err = SecKeychainAddGenericPassword (nil,
                                             realmlen, realm,
                                             namelen, name,
                                             strlen (in_password), in_password,
                                             &itemRef);

        if (err == errSecDuplicateItem) {
            /* We've already stored a password for this principal
             * but it might have changed so update it */
            void *buffer = NULL;
            UInt32 length = 0;

            err = SecKeychainFindGenericPassword (nil,
                                                  realmlen, realm,
                                                  namelen, name,
                                                  &length, &buffer,
                                                  &itemRef);

            if (!err) {
                SecKeychainAttribute attrs[] = {
                    { kSecAccountItemAttr, namelen,  (char *) name },
                    { kSecServiceItemAttr, realmlen, (char *) realm } };
                UInt32 count = sizeof(attrs) / sizeof(attrs[0]);
                const SecKeychainAttributeList attrList = { count, attrs };

                err = SecKeychainItemModifyAttributesAndData (itemRef,
                                                              &attrList,
                                                              strlen (in_password),
                                                              in_password);
            }

        } else if (!err) {
            /* We added a new entry, add a descriptive label */
            SecKeychainAttributeList *copiedAttrs = NULL;
            SecKeychainAttributeInfo attrInfo;
            UInt32 tag = 7;
            UInt32 format = CSSM_DB_ATTRIBUTE_FORMAT_STRING;
            kim_string label = NULL;

            attrInfo.count = 1;
            attrInfo.tag = &tag;
            attrInfo.format = &format;

            err = SecKeychainItemCopyAttributesAndData (itemRef, &attrInfo,
                                                        NULL, &copiedAttrs,
                                                        0, NULL);

            if (!err) {
                /* Label format used by Apple patches */
                err = kim_string_create_from_format (&label, "%s (%s)",
                                                     realm, name);
            }

            if (!err) {
                SecKeychainAttributeList attrList;
                SecKeychainAttribute attr;

                /* Copy the tag they gave us and copy in our label */
                attr.tag = copiedAttrs->attr->tag;
                attr.length = strlen (label);
                attr.data = (char *) label;

                attrList.count = 1;
                attrList.attr = &attr;

                /* And modify. */
                err = SecKeychainItemModifyAttributesAndData (itemRef, &attrList,
                                                              0, NULL);
            }

            if (label      ) { kim_string_free (&label); }
            if (copiedAttrs) { SecKeychainItemFreeAttributesAndData (copiedAttrs, NULL); }
        }

        if (itemRef) { CFRelease (itemRef); }
    }

    kim_string_free (&name);
    kim_string_free (&realm);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_identity_remove_saved_password (kim_identity in_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_string realm = NULL;
    kim_string name = NULL;

    if (!err && !in_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err && !kim_library_allow_home_directory_access ()) {
        return KIM_NO_ERROR; /* simulate no error */
    }

    if (!err) {
        err = kim_identity_get_components_string (in_identity, &name);
    }

    if (!err) {
        err = kim_identity_get_realm (in_identity, &realm);
    }

    if (!err) {
        SecKeychainItemRef itemRef = NULL;
        UInt32 namelen = strlen (name);
        UInt32 realmlen = strlen (realm);
        void *buffer = NULL;
        UInt32 length = 0;

        err = SecKeychainFindGenericPassword (nil,
                                              realmlen, realm,
                                              namelen, name,
                                              &length, &buffer,
                                              &itemRef);

        if (!err) {
            err = SecKeychainItemDelete (itemRef);

        } else if (err == errSecItemNotFound) {
            err = KIM_NO_ERROR; /* No password not an error */
        }

        if (itemRef) { CFRelease (itemRef); }
    }

    kim_string_free (&name);
    kim_string_free (&realm);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_identity_create_for_username (kim_identity *out_identity)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        struct passwd *pw = getpwuid (getuid ());
        if (pw) {
            err =  kim_identity_create_from_string (out_identity, pw->pw_name);
        } else {
            *out_identity = KIM_IDENTITY_ANY;
        }
    }

    return check_error (err);
}
