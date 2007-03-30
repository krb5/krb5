/*
* Copyright (c) 2005 Massachusetts Institute of Technology
*
* Permission is hereby granted, free of charge, to any person
* obtaining a copy of this software and associated documentation
* files (the "Software"), to deal in the Software without
* restriction, including without limitation the rights to use, copy,
* modify, merge, publish, distribute, sublicense, and/or sell copies
* of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
* BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
* ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

/* $Id$ */

#include<shlwapi.h>
#include<kconfiginternal.h>
#include<netidmgr_intver.h>
#include<assert.h>

kconf_conf_space * conf_root = NULL;
kconf_handle * conf_handles = NULL;
kconf_handle * conf_free_handles = NULL;

CRITICAL_SECTION cs_conf_global;
CRITICAL_SECTION cs_conf_handle;
LONG conf_init = 0;
LONG conf_status = 0;

void init_kconf(void) {
    if(InterlockedIncrement(&conf_init) == 1L) {
        /* we are the first */
        InitializeCriticalSection(&cs_conf_global);
        EnterCriticalSection(&cs_conf_global);
        conf_root = khcint_create_empty_space();
        conf_root->name = PWCSDUP(L"Root");
        conf_root->regpath = PWCSDUP(CONFIG_REGPATHW);
        conf_root->refcount++;
        conf_status = 1;
        InitializeCriticalSection(&cs_conf_handle);
        LeaveCriticalSection(&cs_conf_global);
    }
    /* else assume we are already initialized */
}

void exit_kconf(void) {
    if(khc_is_config_running()) {
        kconf_handle * h;

        EnterCriticalSection(&cs_conf_global);

        conf_init = 0;
        conf_status = 0;

        khcint_free_space(conf_root);

        LeaveCriticalSection(&cs_conf_global);
        DeleteCriticalSection(&cs_conf_global);

        EnterCriticalSection(&cs_conf_handle);
        while(conf_free_handles) {
            LPOP(&conf_free_handles, &h);
            if(h) {
                PFREE(h);
            }
        }

        while(conf_handles) {
            LPOP(&conf_handles, &h);
            if(h) {
                PFREE(h);
            }
        }
        LeaveCriticalSection(&cs_conf_handle);
        DeleteCriticalSection(&cs_conf_handle);
    }
}

#if defined(DEBUG) && (defined(KH_BUILD_PRIVATE) || defined(KH_BUILD_SPECIAL))

#include<stdio.h>

static void
khcint_dump_space(FILE * f, kconf_conf_space * sp) {

    kconf_conf_space * sc;

    fprintf(f, "c12\t[%S]\t[%S]\t%d\t0x%x\tWin(%s|%s)|%s\n",
            ((sp->regpath) ? sp->regpath : L"!No Reg path"),
            sp->name,
            (int) sp->refcount,
            (int) sp->flags,
            ((sp->regkey_user)? "HKCU" : ""),
            ((sp->regkey_machine)? "HKLM" : ""),
            ((sp->schema)? "Schema" : ""));


    sc = TFIRSTCHILD(sp);
    while(sc) {

        khcint_dump_space(f, sc);

        sc = LNEXT(sc);
    }
}

KHMEXP void KHMAPI
khcint_dump_handles(FILE * f) {
    if (khc_is_config_running()) {
        kconf_handle * h, * sh;

        EnterCriticalSection(&cs_conf_handle);
        EnterCriticalSection(&cs_conf_global);

        fprintf(f, "c00\t*** Active handles ***\n");
        fprintf(f, "c01\tHandle\tName\tFlags\tRegpath\n");

        h = conf_handles;
        while(h) {
            kconf_conf_space * sp;

            sp = h->space;

            if (!khc_is_handle(h) || sp == NULL) {

                fprintf(f, "c02\t!!INVALID HANDLE!!\n");

            } else {

                fprintf(f, "c02\t0x%p\t[%S]\t0x%x\t[%S]\n",
                        h,
                        sp->name,
                        h->flags,
                        sp->regpath);

                sh = khc_shadow(h);

                while(sh) {

                    sp = sh->space;

                    if (!khc_is_handle(sh) || sp == NULL) {

                        fprintf(f, "c02\t0x%p:Shadow:0x%p\t[!!INVALID HANDLE!!]\n",
                                h, sh);

                    } else {

                        fprintf(f, "c02\t0x%p:Shadow:0x%p,[%S]\t0x%x\t[%S]\n",
                                h, sh,
                                sp->name,
                                sh->flags,
                                sp->regpath);

                    }

                    sh = khc_shadow(sh);
                }

            }

            h = LNEXT(h);
        }

        fprintf(f, "c03\t------  End ---------\n");

        fprintf(f, "c10\t*** Active Configuration Spaces ***\n");
        fprintf(f, "c11\tReg path\tName\tRefcount\tFlags\tLayers\n");

        khcint_dump_space(f, conf_root);

        fprintf(f, "c13\t------  End ---------\n");

        LeaveCriticalSection(&cs_conf_global);
        LeaveCriticalSection(&cs_conf_handle);

    } else {
        fprintf(f, "c00\t------- KHC Configuration not running -------\n");
    }
}

#endif

/* obtains cs_conf_handle/cs_conf_global */
kconf_handle * 
khcint_handle_from_space(kconf_conf_space * s, khm_int32 flags)
{
    kconf_handle * h;

    EnterCriticalSection(&cs_conf_handle);
    LPOP(&conf_free_handles, &h);
    if(!h) {
        h = PMALLOC(sizeof(kconf_handle));
        assert(h != NULL);
    }
    ZeroMemory((void *) h, sizeof(kconf_handle));

    h->magic = KCONF_HANDLE_MAGIC;
    khcint_space_hold(s);
    h->space = s;
    h->flags = flags;

    LPUSH(&conf_handles, h);
    LeaveCriticalSection(&cs_conf_handle);

    return h;
}

/* obtains cs_conf_handle/cs_conf_global */
void 
khcint_handle_free(kconf_handle * h)
{
    kconf_handle * lower;

    EnterCriticalSection(&cs_conf_handle);
#ifdef DEBUG
    /* check if the handle is actually in use */
    {
        kconf_handle * a;
        a = conf_handles;
        while(a) {
            if(h == a)
                break;
            a = LNEXT(a);
        }

        if(a == NULL) {
            DebugBreak();

            /* hmm.  the handle was not in the in-use list */
            LeaveCriticalSection(&cs_conf_handle);
            return;
        }
    }
#endif
    while(h) {
        LDELETE(&conf_handles, h);
        if(h->space) {
            khcint_space_release(h->space);
            h->space = NULL;
        }
        lower = h->lower;
        h->magic = 0;
        LPUSH(&conf_free_handles, h);
        h = lower;
    }
    LeaveCriticalSection(&cs_conf_handle);
}

/* obains cs_conf_handle/cs_conf_global */
kconf_handle * 
khcint_handle_dup(kconf_handle * o)
{
    kconf_handle * h;
    kconf_handle * r;

    r = khcint_handle_from_space(o->space, o->flags);
    h = r;

    while(o->lower) {
        h->lower = khcint_handle_from_space(o->lower->space, o->lower->flags);

        o = o->lower;
        h = h->lower;
    }

    return r;
}

/* obtains cs_conf_global */
void 
khcint_space_hold(kconf_conf_space * s) {
    EnterCriticalSection(&cs_conf_global);
    s->refcount ++;
    LeaveCriticalSection(&cs_conf_global);
}

/* called with cs_conf_global */
void
khcint_try_free_space(kconf_conf_space * s) {

    if (TFIRSTCHILD(s) == NULL &&
        s->refcount == 0 &&
        s->schema == NULL) {

        kconf_conf_space * p;

        p = TPARENT(s);

        if (p == NULL)
            return;

        TDELCHILD(p, s);

        khcint_free_space(s);

        khcint_try_free_space(p);
    }
}

/* obtains cs_conf_global */
void 
khcint_space_release(kconf_conf_space * s) {
    khm_int32 l;

    EnterCriticalSection(&cs_conf_global);

    l = -- s->refcount;
    if (l == 0) {
        if(s->regkey_machine)
            RegCloseKey(s->regkey_machine);
        if(s->regkey_user)
            RegCloseKey(s->regkey_user);
        s->regkey_machine = NULL;
        s->regkey_user = NULL;

        if (s->flags &
            (KCONF_SPACE_FLAG_DELETE_M |
             KCONF_SPACE_FLAG_DELETE_U)) {
            khcint_remove_space(s, s->flags);
        } else {
#ifdef USE_TRY_FREE
            /* even if the refcount is zero, we shouldn't free a
               configuration space just yet since that doesn't play
               well with the configuration space enumeration mechanism
               which expects the spaces to dangle around if there is a
               corresponding registry key or schema. */
            khcint_try_free_space(s);
#endif
        }
    }

    LeaveCriticalSection(&cs_conf_global);
}

/* case sensitive replacement for RegOpenKeyEx */
LONG 
khcint_RegOpenKeyEx(HKEY hkey, LPCWSTR sSubKey, DWORD ulOptions,
                    REGSAM samDesired, PHKEY phkResult) {
    int i;
    wchar_t sk_name[KCONF_MAXCCH_NAME];
    FILETIME ft;
    size_t cch;
    HKEY hkp = NULL;
    const wchar_t * t;
    LONG rv = ERROR_SUCCESS;

    hkp = hkey;
    t = sSubKey;

    /* check for case insensitive prefix first */
    if (!_wcsnicmp(sSubKey, CONFIG_REGPATHW, ARRAYLENGTH(CONFIG_REGPATHW) - 1)) {
        HKEY hkt;

        t = sSubKey + (ARRAYLENGTH(CONFIG_REGPATHW) - 1);

#ifdef DEBUG
        assert(*t == L'\0' || *t == L'\\');
#endif

        rv = RegOpenKeyEx(hkp,
                          CONFIG_REGPATHW,
                          ulOptions,
                          samDesired,
                          &hkt);

        if (rv != ERROR_SUCCESS)
            return rv;

        if (*t == L'\0') {
            *phkResult = hkt;
            return rv;
        }

        t++;
        hkp = hkt;
    }

    /* descend down the components of the subkey */
    while(TRUE) {
        wchar_t * slash;
        HKEY hkt;

        slash = wcschr(t, L'\\');
        if (slash == NULL)
            break;

        if (FAILED(StringCchCopyN(sk_name, ARRAYLENGTH(sk_name),
                                  t, slash - t))) {
            rv = ERROR_CANTOPEN;
            goto _cleanup;
        }

        sk_name[slash - t] = L'\0';
        t = slash+1;

        if (khcint_RegOpenKeyEx(hkp, sk_name, ulOptions, samDesired, &hkt) ==
            ERROR_SUCCESS) {

            if (hkp != hkey)
                RegCloseKey(hkp);
            hkp = hkt;

        } else {

            rv = ERROR_CANTOPEN;
            goto _cleanup;

        }
    }

    /* by now hkp is a handle to the parent of the last component in
       the subkey.  t is a pointer to the last component. */

    if (FAILED(StringCchLength(t, KCONF_MAXCCH_NAME, &cch))) {
        rv = ERROR_CANTOPEN;
        goto _cleanup;
    }

    /* go through and find the case sensitive match for the key */

    for (i=0; ;i++) {
        LONG l;
        DWORD dw;

        dw = ARRAYLENGTH(sk_name);
        l = RegEnumKeyEx(hkp, i, sk_name, &dw,
                         NULL, NULL, NULL, &ft);

        if (l != ERROR_SUCCESS) {
            rv = ERROR_CANTOPEN;
            goto _cleanup;
        }

        if (!(wcsncmp(sk_name, t, cch))) {
            /* bingo! ?? */
            if (cch < KCONF_MAXCCH_NAME &&
                (sk_name[cch] == L'\0' ||
                 sk_name[cch] == L'~')) {
                rv = RegOpenKeyEx(hkp, sk_name, ulOptions,
                                  samDesired, phkResult);
                goto _cleanup;
            }
        }
    }

 _cleanup:
    if (hkp != hkey && hkp != NULL)
        RegCloseKey(hkp);

    return rv;
}

/*! \internal

 \note This function is not a good replacement for RegDeleteKey since
     it deletes all the subkeys in addition to the key being deleted.
 */
LONG
khcint_RegDeleteKey(HKEY hKey,
                    LPCWSTR lpSubKey) {
    int i;
    wchar_t sk_name[KCONF_MAXCCH_NAME];
    FILETIME ft;
    size_t cch;
    LONG rv = ERROR_SUCCESS;

    /* go through and find the case sensitive match for the key */

    if (FAILED(StringCchLength(lpSubKey, KCONF_MAXCCH_NAME, &cch)))
        return ERROR_BADKEY;

    for (i=0; ;i++) {
        LONG l;
        DWORD dw;

        dw = ARRAYLENGTH(sk_name);
        l = RegEnumKeyEx(hKey, i, sk_name, &dw,
                         NULL, NULL, NULL, &ft);

        if (l != ERROR_SUCCESS) {
            rv = ERROR_BADKEY;
            goto _cleanup;
        }

        if (!(wcsncmp(sk_name, lpSubKey, cch))) {
            /* bingo! ?? */
            if ((sk_name[cch] == L'\0' ||
                 sk_name[cch] == L'~')) {

                /* instead of calling RegDeleteKey we call SHDeleteKey
                   because we want to blow off all the subkeys as
                   well.  This is different from the behavior of
                   RegDeleteKey making khcint_RegDeleteKey not a very
                   good case sensitive replacement for
                   RegDeleteKey. */

                rv = SHDeleteKey(hKey, sk_name);
                goto _cleanup;
            }
        }
    }

 _cleanup:
    return rv;
}

LONG
khcint_RegCreateKeyEx(HKEY hKey,
                      LPCWSTR lpSubKey,
                      DWORD Reserved,
                      LPWSTR lpClass,
                      DWORD dwOptions,
                      REGSAM samDesired,
                      LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                      PHKEY phkResult,
                      LPDWORD lpdwDisposition) {
    LONG l;
    int i;
    long index = 0;
    wchar_t sk_name[KCONF_MAXCCH_NAME]; /* hard limit in Windows */
    FILETIME ft;
    size_t cch;
    const wchar_t * t;
    LONG rv = ERROR_SUCCESS;
    HKEY hkp = NULL;

    hkp = hKey;
    t = lpSubKey;

    /* check for case insensitive prefix first */
    if (!_wcsnicmp(lpSubKey, CONFIG_REGPATHW, ARRAYLENGTH(CONFIG_REGPATHW) - 1)) {
        HKEY hkt;

        t = lpSubKey + (ARRAYLENGTH(CONFIG_REGPATHW) - 1);

#ifdef DEBUG
        assert(*t == L'\0' || *t == L'\\');
#endif

        rv = RegCreateKeyEx(hkp,
                            CONFIG_REGPATHW,
                            Reserved,
                            lpClass,
                            dwOptions,
                            samDesired,
                            lpSecurityAttributes,
                            &hkt,
                            lpdwDisposition);

        if (rv != ERROR_SUCCESS)
            return rv;

        if (*t == L'\0') {
            *phkResult = hkt;
            return rv;
        }

        t++;
        hkp = hkt;
    }

    while(TRUE) {
        wchar_t * slash;
        HKEY hkt;

        slash = wcschr(t, L'\\');
        if (slash == NULL)
            break;

        if (FAILED(StringCchCopyN(sk_name, ARRAYLENGTH(sk_name),
                                  t, slash - t))) {
            rv = ERROR_CANTOPEN;
            goto _cleanup;
        }

        sk_name[slash - t] = L'\0';
        t = slash+1;

        if (khcint_RegOpenKeyEx(hkp, sk_name, 0, samDesired, &hkt) ==
            ERROR_SUCCESS) {

            if (hkp != hKey)
                RegCloseKey(hkp);
            hkp = hkt;
        } else {

            rv = RegCreateKeyEx(hKey,
                                lpSubKey,
                                Reserved,
                                lpClass,
                                dwOptions,
                                samDesired,
                                lpSecurityAttributes,
                                phkResult,
                                lpdwDisposition);
            goto _cleanup;
        }
    }

    if (FAILED(StringCchLength(t, KCONF_MAXCCH_NAME, &cch))) {
        rv = ERROR_CANTOPEN;
        goto _cleanup;
    }

    for (i=0; ;i++) {
        DWORD dw;

        dw = ARRAYLENGTH(sk_name);
        l = RegEnumKeyEx(hkp, i, sk_name, &dw,
                         NULL, NULL, NULL, &ft);

        if (l != ERROR_SUCCESS)
            break;

        if (!(wcsncmp(sk_name, t, cch))) {
            /* bingo! ?? */
            if (sk_name[cch] == L'\0' ||
                sk_name[cch] == L'~') {
                l = RegOpenKeyEx(hkp, sk_name, 0,
                                 samDesired, phkResult);
                if (l == ERROR_SUCCESS && lpdwDisposition)
                    *lpdwDisposition = REG_OPENED_EXISTING_KEY;
                rv = l;
                goto _cleanup;
            }
        }

        if (!_wcsnicmp(sk_name, t, cch) &&
            (sk_name[cch] == L'\0' ||
             sk_name[cch] == L'~')) {
            long new_idx;

            if (sk_name[cch] == L'\0')
                new_idx = 1;
            else if (cch + 1 < KCONF_MAXCCH_NAME)
                new_idx = wcstol(sk_name + (cch + 1), NULL, 10);
            else
                return ERROR_BUFFER_OVERFLOW;

            assert(new_idx > 0);

            if (new_idx > index)
                index = new_idx;
        }
    }

    if (index != 0) {
        if (FAILED(StringCbPrintf(sk_name, sizeof(sk_name),
                                  L"%s~%d", t, index)))
            return ERROR_BUFFER_OVERFLOW;
    } else {
        StringCbCopy(sk_name, sizeof(sk_name), t);
    }

    rv = RegCreateKeyEx(hkp,
                        sk_name,
                        Reserved,
                        lpClass,
                        dwOptions,
                        samDesired,
                        lpSecurityAttributes,
                        phkResult,
                        lpdwDisposition);

 _cleanup:

    if (hkp != hKey && hkp != NULL)
        RegCloseKey(hkp);

    return rv;
}

/* obtains cs_conf_global */
HKEY 
khcint_space_open_key(kconf_conf_space * s, khm_int32 flags) {
    HKEY hk = NULL;
    int nflags = 0;
    DWORD disp;
    if(flags & KCONF_FLAG_MACHINE) {
        if(s->regkey_machine)
            return s->regkey_machine;
        if((khcint_RegOpenKeyEx(HKEY_LOCAL_MACHINE, s->regpath, 0, 
                                KEY_READ | KEY_WRITE, &hk) != 
            ERROR_SUCCESS) && 
           !(flags & KHM_PERM_WRITE)) {

            if(khcint_RegOpenKeyEx(HKEY_LOCAL_MACHINE, s->regpath, 0, 
                                   KEY_READ, &hk) == ERROR_SUCCESS) {
                nflags = KHM_PERM_READ;
            }

        }
        if(!hk && (flags & KHM_FLAG_CREATE)) {

            khcint_RegCreateKeyEx(HKEY_LOCAL_MACHINE, 
                                  s->regpath, 
                                  0,
                                  NULL,
                                  REG_OPTION_NON_VOLATILE,
                                  KEY_READ | KEY_WRITE,
                                  NULL,
                                  &hk,
                                  &disp);
        }
        if(hk) {
            EnterCriticalSection(&cs_conf_global);
            s->regkey_machine = hk;
            s->regkey_machine_flags = nflags;
            LeaveCriticalSection(&cs_conf_global);
        }

        return hk;
    } else {
        if(s->regkey_user)
            return s->regkey_user;
        if((khcint_RegOpenKeyEx(HKEY_CURRENT_USER, s->regpath, 0, 
                                KEY_READ | KEY_WRITE, &hk) != 
            ERROR_SUCCESS) && 
           !(flags & KHM_PERM_WRITE)) {
            if(khcint_RegOpenKeyEx(HKEY_CURRENT_USER, s->regpath, 0, 
                                   KEY_READ, &hk) == ERROR_SUCCESS) {
                nflags = KHM_PERM_READ;
            }
        }
        if(!hk && (flags & KHM_FLAG_CREATE)) {
            khcint_RegCreateKeyEx(HKEY_CURRENT_USER, 
                                  s->regpath, 0, NULL,
                                  REG_OPTION_NON_VOLATILE,
                                  KEY_READ | KEY_WRITE,
                                  NULL, &hk, &disp);
        }
        if(hk) {
            EnterCriticalSection(&cs_conf_global);
            s->regkey_user = hk;
            s->regkey_user_flags = nflags;
            LeaveCriticalSection(&cs_conf_global);
        }

        return hk;
    }
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_shadow_space(khm_handle upper, khm_handle lower)
{
    kconf_handle * h;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!khc_is_handle(upper)) {
#ifdef DEBUG
        DebugBreak();
#endif
        return KHM_ERROR_INVALID_PARAM;
    }

    h = (kconf_handle *) upper;

    EnterCriticalSection(&cs_conf_handle);
    if(h->lower) {
        EnterCriticalSection(&cs_conf_global);
        khcint_handle_free(h->lower);
        LeaveCriticalSection(&cs_conf_global);
        h->lower = NULL;
    }

    if(khc_is_handle(lower)) {
        kconf_handle * l;
        kconf_handle * lc;

        l = (kconf_handle *) lower;
        lc = khcint_handle_dup(l);
        h->lower = lc;
    }
    LeaveCriticalSection(&cs_conf_handle);

    return KHM_ERROR_SUCCESS;
}

/* no locks */
kconf_conf_space * 
khcint_create_empty_space(void) {
    kconf_conf_space * r;

    r = PMALLOC(sizeof(kconf_conf_space));
    assert(r != NULL);
    ZeroMemory(r,sizeof(kconf_conf_space));

    return r;
}

/* called with cs_conf_global */
void 
khcint_free_space(kconf_conf_space * r) {
    kconf_conf_space * c;

    if(!r)
        return;

    TPOPCHILD(r, &c);
    while(c) {
        khcint_free_space(c);
        TPOPCHILD(r, &c);
    }

    if(r->name)
        PFREE(r->name);

    if(r->regpath)
        PFREE(r->regpath);

    if(r->regkey_machine)
        RegCloseKey(r->regkey_machine);

    if(r->regkey_user)
        RegCloseKey(r->regkey_user);

    PFREE(r);
}

/* obtains cs_conf_global */
khm_int32 
khcint_open_space(kconf_conf_space * parent, 
                  const wchar_t * sname, size_t n_sname, 
                  khm_int32 flags, kconf_conf_space **result) {
    kconf_conf_space * p;
    kconf_conf_space * c;
    HKEY pkey = NULL;
    HKEY ckey = NULL;
    wchar_t buf[KCONF_MAXCCH_NAME];
    size_t cb_regpath = 0;

    if(!parent)
        p = conf_root;
    else
        p = parent;

    if(n_sname >= KCONF_MAXCCH_NAME || n_sname <= 0)
        return KHM_ERROR_INVALID_PARAM;

    StringCchCopyN(buf, ARRAYLENGTH(buf), sname, n_sname);

    /* see if there is already a config space by this name. if so,
       return it.  Note that if the configuration space is specified
       in a schema, we would find it here. */
    EnterCriticalSection(&cs_conf_global);
    c = TFIRSTCHILD(p);
    while(c) {
        if(c->name && !wcscmp(c->name, buf))
            break;

        c = LNEXT(c);
    }
    LeaveCriticalSection(&cs_conf_global);

    if(c) {

        if (c->flags & KCONF_SPACE_FLAG_DELETED) {
            if (flags & KHM_FLAG_CREATE) {
                c->flags &= ~(KCONF_SPACE_FLAG_DELETED |
                              KCONF_SPACE_FLAG_DELETE_M |
                              KCONF_SPACE_FLAG_DELETE_U);
            } else {
                *result = NULL;
                return KHM_ERROR_NOT_FOUND;
            }
        }

        khcint_space_hold(c);
        *result = c;
        return KHM_ERROR_SUCCESS;
    }

    if(!(flags & KHM_FLAG_CREATE)) {

        /* we are not creating the space, so it must exist in the form of a
        registry key in HKLM or HKCU.  If it existed as a schema, we
        would have already retured it above. */
        
        if (flags & KCONF_FLAG_USER)
            pkey = khcint_space_open_key(p, KHM_PERM_READ | KCONF_FLAG_USER);

        if((!pkey ||
            (khcint_RegOpenKeyEx(pkey, buf, 0, KEY_READ, &ckey) !=
             ERROR_SUCCESS))
           && (flags & KCONF_FLAG_MACHINE)) {

            pkey = khcint_space_open_key(p, KHM_PERM_READ | KCONF_FLAG_MACHINE);
            if(!pkey ||
               (khcint_RegOpenKeyEx(pkey, buf, 0, KEY_READ, &ckey) !=
                ERROR_SUCCESS)) {
                *result = NULL;

                return KHM_ERROR_NOT_FOUND;
            }
        }

        if(ckey) {
            RegCloseKey(ckey);
            ckey = NULL;
        }
    }

    c = khcint_create_empty_space();
    
    /*SAFE: buf: is of known length < KCONF_MAXCCH_NAME */
    c->name = PWCSDUP(buf);

    /*SAFE: p->regpath: is valid since it was set using this same
      function. */
    /*SAFE: buf: see above */
    cb_regpath = (wcslen(p->regpath) + wcslen(buf) + 2) * sizeof(wchar_t);
    c->regpath = PMALLOC(cb_regpath);

    assert(c->regpath != NULL);

    /*SAFE: c->regpath: allocated above to be big enough */
    /*SAFE: p->regpath: see above */
    StringCbCopy(c->regpath, cb_regpath, p->regpath);
    StringCbCat(c->regpath, cb_regpath, L"\\");

    /*SAFE: buf: see above */
    StringCbCat(c->regpath, cb_regpath, buf);

    khcint_space_hold(c);

    EnterCriticalSection(&cs_conf_global);
    TADDCHILD(p,c);
    LeaveCriticalSection(&cs_conf_global);

    *result = c;
    return KHM_ERROR_SUCCESS;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_open_space(khm_handle parent, const wchar_t * cspace, khm_int32 flags, 
               khm_handle * result) {
    kconf_handle * h;
    kconf_conf_space * p;
    kconf_conf_space * c = NULL;
    size_t cbsize;
    const wchar_t * str;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running()) {
        return KHM_ERROR_NOT_READY;
    }

    if(!result || (parent && !khc_is_handle(parent))) {
#ifdef DEBUG
        DebugBreak();
#endif
        return KHM_ERROR_INVALID_PARAM;
    }

    if(!parent)
        p = conf_root;
    else {
        h = (kconf_handle *) parent;
        p = khc_space_from_handle(parent);
    }

    khcint_space_hold(p);

    /* if none of these flags are specified, make it seem like all of
       them were */
    if(!(flags & KCONF_FLAG_USER) &&
        !(flags & KCONF_FLAG_MACHINE) &&
        !(flags & KCONF_FLAG_SCHEMA))
        flags |= KCONF_FLAG_USER | KCONF_FLAG_MACHINE | KCONF_FLAG_SCHEMA;

    if(cspace == NULL) {
        *result = (khm_handle) khcint_handle_from_space(p, flags);
        khcint_space_release(p);
        return KHM_ERROR_SUCCESS;
    }

    if(FAILED(StringCbLength(cspace, KCONF_MAXCB_PATH, &cbsize))) {
        khcint_space_release(p);
        *result = NULL;
        return KHM_ERROR_INVALID_PARAM;
    }

    str = cspace;
    while(TRUE) {
        const wchar_t * end = NULL;

        if (!(flags & KCONF_FLAG_NOPARSENAME)) {

            end = wcschr(str, L'\\'); /* safe because cspace was
                                     validated above */
        }

        if(!end) {
            if(flags & KCONF_FLAG_TRAILINGVALUE) {
                /* we are at the value component */
                c = p;
                khcint_space_hold(c);
                break;
            } else
                end = str + wcslen(str);  /* safe because cspace was
                                             validated above */
        }

        rv = khcint_open_space(p, str, end - str, flags, &c);

        if(KHM_SUCCEEDED(rv) && (*end == L'\\')) {
            khcint_space_release(p);
            p = c;
            c = NULL;
            str = end+1;
        }
        else
            break;
    }

    khcint_space_release(p);
    if(KHM_SUCCEEDED(rv)) {
        *result = khcint_handle_from_space(c, flags);
    } else
        *result = NULL;

    if (c)
        khcint_space_release(c);

    return rv;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_close_space(khm_handle csp) {
    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!khc_is_handle(csp)) {
#ifdef DEBUG
        DebugBreak();
#endif
        return KHM_ERROR_INVALID_PARAM;
    }

    khcint_handle_free((kconf_handle *) csp);
    return KHM_ERROR_SUCCESS;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_read_string(khm_handle pconf, 
                const wchar_t * pvalue, 
                wchar_t * buf, 
                khm_size * bufsize) 
{
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    do {
        HKEY hku = NULL;
        HKEY hkm = NULL;
        const wchar_t * value = NULL;
        int free_space = 0;
        khm_handle conf = NULL;
        DWORD size;
        DWORD type;
        LONG hr;

        int i;

        if((value = wcsrchr(pvalue, L'\\')) != NULL) {

            if(KHM_FAILED(khc_open_space(
                pconf, 
                pvalue, 
                KCONF_FLAG_TRAILINGVALUE | (pconf?khc_handle_flags(pconf):0), 
                &conf)))
                goto _shadow;

            free_space = 1;

            if (value) {
                value++;
            } else {
#ifdef DEBUG
                assert(FALSE);
#endif
            }
        } else {
            value = pvalue;
            conf = pconf;
            free_space = 0;
        }

        if(!khc_is_handle(conf))
            goto _shadow;

        c = khc_space_from_handle(conf);

        if(khc_is_user_handle(conf))
            hku = khcint_space_open_key(c, KHM_PERM_READ);

        if(khc_is_machine_handle(conf))
            hkm = khcint_space_open_key(c, KHM_PERM_READ | KCONF_FLAG_MACHINE);

        size = (DWORD) *bufsize;
        if(hku) {
            hr = RegQueryValueEx(hku, value, NULL, &type, (LPBYTE) buf, &size);
            if(hr == ERROR_SUCCESS) {
                if(type != REG_SZ) {
                    rv = KHM_ERROR_TYPE_MISMATCH;
                    goto _exit;
                }
                else {
                    *bufsize = size;
                    /* if buf==NULL, RegQueryValueEx will return success and just return the
                       required buffer size in 'size' */
                    rv = (buf)? KHM_ERROR_SUCCESS: KHM_ERROR_TOO_LONG;
                    goto _exit;
                }
            } else {
                if(hr == ERROR_MORE_DATA) {
                    *bufsize = size;
                    rv = KHM_ERROR_TOO_LONG;
                    goto _exit;
                }
            }
        }

        size = (DWORD) *bufsize;
        if(hkm) {
            hr = RegQueryValueEx(hkm, value, NULL, &type, (LPBYTE) buf, &size);
            if(hr == ERROR_SUCCESS) {
                if(type != REG_SZ) {
                    rv = KHM_ERROR_TYPE_MISMATCH;
                    goto _exit;
                }
                else {
                    *bufsize = size;
                    rv = (buf)? KHM_ERROR_SUCCESS: KHM_ERROR_TOO_LONG;
                    goto _exit;
                }
            } else {
                if(hr == ERROR_MORE_DATA) {
                    *bufsize = size;
                    rv = KHM_ERROR_TOO_LONG;
                    goto _exit;
                }
            }
        }

        if(c->schema && khc_is_schema_handle(conf)) {
            for(i=0;i<c->nSchema;i++) {
                if(c->schema[i].type == KC_STRING && !wcscmp(value, c->schema[i].name)) {
                    /* found it */
                    size_t cbsize = 0;

                    if(!c->schema[i].value) {
                        rv = KHM_ERROR_NOT_FOUND;
                        goto _exit;
                    }

                    if(FAILED(StringCbLength((wchar_t *) c->schema[i].value, KCONF_MAXCB_STRING, &cbsize))) {
                        rv = KHM_ERROR_NOT_FOUND;
                        goto _exit;
                    }
                    cbsize += sizeof(wchar_t);

                    if(!buf || *bufsize < cbsize) {
                        *bufsize = cbsize;
                        rv = KHM_ERROR_TOO_LONG;
                        goto _exit;
                    }

                    StringCbCopy(buf, *bufsize, (wchar_t *) c->schema[i].value);
                    *bufsize = cbsize;
                    rv = KHM_ERROR_SUCCESS;
                    goto _exit;
                }
            }
        }

_shadow:
        if(free_space && conf)
            khc_close_space(conf);

        if(khc_is_shadowed(pconf)) {
            pconf = khc_shadow(pconf);
            continue;
        } else {
            rv = KHM_ERROR_NOT_FOUND;
            break;
        }

_exit:
        if(free_space && conf)
            khc_close_space(conf);
        break;

    } while(TRUE);

    return rv;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_read_int32(khm_handle pconf, const wchar_t * pvalue, khm_int32 * buf) {
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!buf || !pvalue)
        return KHM_ERROR_INVALID_PARAM;

    do {
        DWORD size;
        DWORD type;
        LONG hr;
        HKEY hku = NULL;
        HKEY hkm = NULL;

        const wchar_t * value = NULL;
        int free_space = 0;
        khm_handle conf = NULL;

        int i;

        if((value = wcsrchr(pvalue, L'\\')) != NULL) {
            if(KHM_FAILED(khc_open_space(
                pconf, 
                pvalue, 
                KCONF_FLAG_TRAILINGVALUE | (pconf?khc_handle_flags(pconf):0), 
                &conf)))
                goto _shadow;
            free_space = 1;

            if (value) {
                value++;
            } else {
#ifdef DEBUG
                assert(FALSE);
#endif
            }
        } else {
            value = pvalue;
            conf = pconf;
            free_space = 0;
        }

        if(!khc_is_handle(conf) || !buf)
            goto _shadow;

        c = khc_space_from_handle(conf);

        if(khc_is_user_handle(conf))
            hku = khcint_space_open_key(c, KHM_PERM_READ);

        if(khc_is_machine_handle(conf))
            hkm = khcint_space_open_key(c, KHM_PERM_READ | KCONF_FLAG_MACHINE);

        size = sizeof(DWORD);
        if(hku) {
            hr = RegQueryValueEx(hku, value, NULL, &type, (LPBYTE) buf, &size);
            if(hr == ERROR_SUCCESS) {
                if(type != REG_DWORD) {
                    rv = KHM_ERROR_TYPE_MISMATCH;
                    goto _exit;
                }
                else {
                    rv = KHM_ERROR_SUCCESS;
                    goto _exit;
                }
            }
        }

        size = sizeof(DWORD);
        if(hkm) {
            hr = RegQueryValueEx(hkm, value, NULL, &type, (LPBYTE) buf, &size);
            if(hr == ERROR_SUCCESS) {
                if(type != REG_DWORD) {
                    rv= KHM_ERROR_TYPE_MISMATCH;
                    goto _exit;
                }
                else {
                    rv=  KHM_ERROR_SUCCESS;
                    goto _exit;
                }
            }
        }

        if(c->schema && khc_is_schema_handle(conf)) {
            for(i=0;i<c->nSchema;i++) {
                if(c->schema[i].type == KC_INT32 && !wcscmp(value, c->schema[i].name)) {
                    *buf = (khm_int32) c->schema[i].value;
                    rv = KHM_ERROR_SUCCESS;
                    goto _exit;
                }
            }
        }
_shadow:
        if(free_space && conf)
            khc_close_space(conf);

        if(khc_is_shadowed(pconf)) {
            pconf = khc_shadow(pconf);
            continue;
        } else {
            rv = KHM_ERROR_NOT_FOUND;
            break;
        }
_exit:
        if(free_space && conf)
            khc_close_space(conf);
        break;
    }
    while(TRUE);

    return rv;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_read_int64(khm_handle pconf, const wchar_t * pvalue, khm_int64 * buf) {
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    do {
        DWORD size;
        DWORD type;
        LONG hr;
        HKEY hku = NULL;
        HKEY hkm = NULL;

        const wchar_t * value = NULL;
        int free_space = 0;
        khm_handle conf = NULL;

        int i;

        if((value = wcsrchr(pvalue, L'\\')) != NULL) {
            if(KHM_FAILED(khc_open_space(
                pconf, 
                pvalue, 
                KCONF_FLAG_TRAILINGVALUE | (pconf?khc_handle_flags(pconf):0), 
                &conf)))
                goto _shadow;
            free_space = 1;

            if (value) {
                value++;
            } else {
#ifdef DEBUG
                assert(FALSE);
#endif
            }
        } else {
            value = pvalue;
            conf = pconf;
            free_space = 0;
        }

        if(!khc_is_handle(conf) || !buf)
            goto _shadow;

        c = khc_space_from_handle(conf);

        if(khc_is_user_handle(conf))
            hku = khcint_space_open_key(c, KHM_PERM_READ);

        if(khc_is_machine_handle(conf))
            hkm = khcint_space_open_key(c, KHM_PERM_READ | KCONF_FLAG_MACHINE);

        size = sizeof(khm_int64);
        if(hku) {
            hr = RegQueryValueEx(hku, value, NULL, &type, (LPBYTE) buf, &size);
            if(hr == ERROR_SUCCESS) {
                if(type != REG_QWORD) {
                    rv= KHM_ERROR_TYPE_MISMATCH;
                    goto _exit;
                }
                else {
                    rv = KHM_ERROR_SUCCESS;
                    goto _exit;
                }
            }
        }

        size = sizeof(khm_int64);
        if(hkm) {
            hr = RegQueryValueEx(hkm, value, NULL, &type, (LPBYTE) buf, &size);
            if(hr == ERROR_SUCCESS) {
                if(type != REG_QWORD) {
                    rv = KHM_ERROR_TYPE_MISMATCH;
                    goto _exit;
                }
                else {
                    rv = KHM_ERROR_SUCCESS;
                    goto _exit;
                }
            }
        }

        if(c->schema && khc_is_schema_handle(conf)) {
            for(i=0;i<c->nSchema;i++) {
                if(c->schema[i].type == KC_INT64 && !wcscmp(value, c->schema[i].name)) {
                    *buf = (khm_int64) c->schema[i].value;
                    rv = KHM_ERROR_SUCCESS;
                    goto _exit;
                }
            }
        }

_shadow:
        if(free_space && conf)
            khc_close_space(conf);
        if(khc_is_shadowed(pconf)) {
            pconf = khc_shadow(pconf);
            continue;
        } else {
            rv = KHM_ERROR_NOT_FOUND;
            break;
        }

_exit:
        if(free_space && conf)
            khc_close_space(conf);
        break;

    } while(TRUE);
    return rv;
}

/* obtaincs cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_read_binary(khm_handle pconf, const wchar_t * pvalue, 
                void * buf, khm_size * bufsize) {
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    do {
        DWORD size;
        DWORD type;
        LONG hr;
        HKEY hku = NULL;
        HKEY hkm = NULL;

        const wchar_t * value = NULL;
        int free_space = 0;
        khm_handle conf = NULL;

        if((value = wcsrchr(pvalue, L'\\')) != NULL) {
            if(KHM_FAILED(khc_open_space(
                pconf, 
                pvalue, 
                KCONF_FLAG_TRAILINGVALUE | (pconf?khc_handle_flags(pconf):0), 
                &conf)))
                goto _shadow;
            free_space = 1;

            if (value) {
                value++;
            } else {
#ifdef DEBUG
                assert(FALSE);
#endif
            }
        } else {
            value = pvalue;
            conf = pconf;
            free_space = 0;
        }

        if(!khc_is_handle(conf))
            goto _shadow;

        c = khc_space_from_handle(conf);

        if(khc_is_user_handle(conf))
            hku = khcint_space_open_key(c, KHM_PERM_READ);

        if(khc_is_machine_handle(conf))
            hkm = khcint_space_open_key(c, KHM_PERM_READ | KCONF_FLAG_MACHINE);

        size = (DWORD) *bufsize;
        if(hku) {
            hr = RegQueryValueEx(hku, value, NULL, &type, (LPBYTE) buf, &size);
            if(hr == ERROR_SUCCESS) {
                if(type != REG_BINARY) {
                    rv = KHM_ERROR_TYPE_MISMATCH;
                    goto _exit;
                }
                else {
                    *bufsize = size;
                    rv =  KHM_ERROR_SUCCESS;
                    goto _exit;
                }
            } else {
                if(hr == ERROR_MORE_DATA) {
                    *bufsize = size;
                    rv = KHM_ERROR_TOO_LONG;
                    goto _exit;
                }
            }
        }

        size = (DWORD) *bufsize;
        if(hkm) {
            hr = RegQueryValueEx(hkm, value, NULL, &type, (LPBYTE) buf, &size);
            if(hr == ERROR_SUCCESS) {
                if(type != REG_BINARY) {
                    rv = KHM_ERROR_TYPE_MISMATCH;
                    goto _exit;
                }
                else {
                    *bufsize = size;
                    rv = KHM_ERROR_SUCCESS;
                    goto _exit;
                }
            } else {
                if(hr == ERROR_MORE_DATA) {
                    *bufsize = size;
                    rv = KHM_ERROR_TOO_LONG;
                    goto _exit;
                }
            }
        }

        /* binary values aren't supported in schema */
_shadow:
        if(free_space && conf)
            khc_close_space(conf);
        if(khc_is_shadowed(pconf)) {
            pconf = khc_shadow(pconf);
            continue;
        } else {
            rv = KHM_ERROR_NOT_FOUND;
            break;
        }

_exit:
        if(free_space && conf)
            khc_close_space(conf);
        break;

    }while (TRUE);

    return rv;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_write_string(khm_handle pconf, 
                 const wchar_t * pvalue, 
                 wchar_t * buf) 
{
    HKEY pk = NULL;
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    LONG hr;
    size_t cbsize;
    const wchar_t * value = NULL;
    int free_space = 0;
    khm_handle conf = NULL;


    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(pconf && !khc_is_machine_handle(pconf) && !khc_is_user_handle(pconf))
        return KHM_ERROR_INVALID_OPERATION;

    if(FAILED(StringCbLength(buf, KCONF_MAXCB_STRING, &cbsize))) {
        rv = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cbsize += sizeof(wchar_t);

    if (khc_handle_flags(pconf) & KCONF_FLAG_WRITEIFMOD) {
        wchar_t tmpbuf[512];
        wchar_t * buffer;
        size_t tmpsize = cbsize;
        khm_boolean is_equal = FALSE;

        if (cbsize <= sizeof(tmpbuf)) {
            buffer = tmpbuf;
        } else {
            buffer = PMALLOC(cbsize);
        }

        if (KHM_SUCCEEDED(khc_read_string(pconf, pvalue, buffer, &tmpsize)) &&
            tmpsize == cbsize) {
            if (khc_handle_flags(pconf) & KCONF_FLAG_IFMODCI)
                is_equal = !_wcsicmp(buffer, buf);
            else
                is_equal = !wcscmp(buffer, buf);
        }

        if (buffer != tmpbuf)
            PFREE(buffer);

        if (is_equal) {
            return KHM_ERROR_SUCCESS;
        }
    }

    if((value = wcsrchr(pvalue, L'\\')) != NULL) {
        if(KHM_FAILED(khc_open_space(pconf, pvalue, 
                                     KCONF_FLAG_TRAILINGVALUE | (pconf?khc_handle_flags(pconf):0), 
                                     &conf)))
            return KHM_ERROR_INVALID_PARAM;
        free_space = 1;

        if (value) {
            value ++;
        } else {
#ifdef DEBUG
            assert(FALSE);
#endif
        }
    } else {
        value = pvalue;
        conf = pconf;
        free_space = 0;
    }

    if(!khc_is_handle(conf) || !buf) {
        rv = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    c = khc_space_from_handle(conf);

    if(khc_is_user_handle(conf)) {
        pk = khcint_space_open_key(c, KHM_PERM_WRITE | KHM_FLAG_CREATE);
    } else {
        pk = khcint_space_open_key(c, KHM_PERM_WRITE | KCONF_FLAG_MACHINE | KHM_FLAG_CREATE);
    }

    hr = RegSetValueEx(pk, value, 0, REG_SZ, (LPBYTE) buf, (DWORD) cbsize);

    if(hr != ERROR_SUCCESS)
        rv = KHM_ERROR_INVALID_OPERATION;

_exit:
    if(free_space)
        khc_close_space(conf);
    return rv;
}

/* obtaincs cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_write_int32(khm_handle pconf, 
                const wchar_t * pvalue, 
                khm_int32 buf) 
{
    HKEY pk = NULL;
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    LONG hr;
    const wchar_t * value = NULL;
    int free_space = 0;
    khm_handle conf = NULL;


    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(pconf && !khc_is_machine_handle(pconf) && !khc_is_user_handle(pconf))
        return KHM_ERROR_INVALID_OPERATION;

    if (khc_handle_flags(pconf) & KCONF_FLAG_WRITEIFMOD) {
        khm_int32 tmpvalue;

        if (KHM_SUCCEEDED(khc_read_int32(pconf, pvalue, &tmpvalue)) &&
            tmpvalue == buf) {
            return KHM_ERROR_SUCCESS;
        }
    }

    if((value = wcsrchr(pvalue, L'\\')) != NULL) {
        if(KHM_FAILED(khc_open_space(
            pconf, 
            pvalue, 
            KCONF_FLAG_TRAILINGVALUE | (pconf?khc_handle_flags(pconf):0), 
            &conf)))
            return KHM_ERROR_INVALID_PARAM;
        free_space = 1;

        if (value) {
            value ++;
        } else {
#ifdef DEBUG
            assert(FALSE);
#endif
        }
    } else {
        value = pvalue;
        conf = pconf;
        free_space = 0;
    }

    if(!khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    c = khc_space_from_handle( conf);

    if(khc_is_user_handle(conf)) {
        pk = khcint_space_open_key(c, KHM_PERM_WRITE | KHM_FLAG_CREATE);
    } else {
        pk = khcint_space_open_key(c, KHM_PERM_WRITE | KCONF_FLAG_MACHINE | KHM_FLAG_CREATE);
    }

    hr = RegSetValueEx(pk, value, 0, REG_DWORD, (LPBYTE) &buf, sizeof(khm_int32));

    if(hr != ERROR_SUCCESS)
        rv = KHM_ERROR_INVALID_OPERATION;

    if(free_space)
        khc_close_space(conf);

    return rv;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_write_int64(khm_handle pconf, const wchar_t * pvalue, khm_int64 buf) {
    HKEY pk = NULL;
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    LONG hr;
    const wchar_t * value = NULL;
    int free_space = 0;
    khm_handle conf = NULL;


    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(pconf && !khc_is_machine_handle(pconf) && !khc_is_user_handle(pconf))
        return KHM_ERROR_INVALID_OPERATION;

    if (khc_handle_flags(pconf) & KCONF_FLAG_WRITEIFMOD) {
        khm_int64 tmpvalue;

        if (KHM_SUCCEEDED(khc_read_int64(pconf, pvalue, &tmpvalue)) &&
            tmpvalue == buf) {
            return KHM_ERROR_SUCCESS;
        }
    }

    if((value = wcsrchr(pvalue, L'\\')) != NULL) {
        if(KHM_FAILED(khc_open_space(
            pconf, 
            pvalue, 
            KCONF_FLAG_TRAILINGVALUE | (pconf?khc_handle_flags(pconf):0), 
            &conf)))
            return KHM_ERROR_INVALID_PARAM;
        free_space = 1;

        if (value) {
            value ++;
        } else {
#ifdef DEBUG
            assert(FALSE);
#endif
        }
    } else {
        value = pvalue;
        conf = pconf;
        free_space = 0;
    }

    if(!khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    c = khc_space_from_handle( conf);

    if(khc_is_user_handle(conf)) {
        pk = khcint_space_open_key(c, KHM_PERM_WRITE | KHM_FLAG_CREATE);
    } else {
        pk = khcint_space_open_key(c, KHM_PERM_WRITE | KCONF_FLAG_MACHINE | KHM_FLAG_CREATE);
    }

    hr = RegSetValueEx(pk, value, 0, REG_QWORD, (LPBYTE) &buf, sizeof(khm_int64));

    if(hr != ERROR_SUCCESS)
        rv = KHM_ERROR_INVALID_OPERATION;

    if(free_space)
        khc_close_space(conf);

    return rv;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_write_binary(khm_handle pconf, 
                 const wchar_t * pvalue, 
                 void * buf, khm_size bufsize) {
    HKEY pk = NULL;
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    LONG hr;
    const wchar_t * value = NULL;
    int free_space = 0;
    khm_handle conf = NULL;


    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(pconf && !khc_is_machine_handle(pconf) && !khc_is_user_handle(pconf))
        return KHM_ERROR_INVALID_OPERATION;

    if((value = wcsrchr(pvalue, L'\\')) != NULL) {
        if(KHM_FAILED(khc_open_space(
            pconf, 
            pvalue, 
            KCONF_FLAG_TRAILINGVALUE | (pconf?khc_handle_flags(pconf):0), 
            &conf)))
            return KHM_ERROR_INVALID_PARAM;
        free_space = 1;

        if (value) {
            value ++;
        } else {
#ifdef DEBUG
            assert(FALSE);
#endif
        }
    } else {
        value = pvalue;
        conf = pconf;
        free_space = 0;
    }

    if(!khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    c = khc_space_from_handle(conf);

    if(khc_is_user_handle(conf)) {
        pk = khcint_space_open_key(c, KHM_PERM_WRITE | KHM_FLAG_CREATE);
    } else {
        pk = khcint_space_open_key(c, KHM_PERM_WRITE | KCONF_FLAG_MACHINE | KHM_FLAG_CREATE);
    }

    hr = RegSetValueEx(pk, value, 0, REG_BINARY, buf, (DWORD) bufsize);

    if(hr != ERROR_SUCCESS)
        rv = KHM_ERROR_INVALID_OPERATION;

    if(free_space)
        khc_close_space(conf);

    return rv;
}

/* no locks */
KHMEXP khm_int32 KHMAPI 
khc_get_config_space_name(khm_handle conf, 
                          wchar_t * buf, khm_size * bufsize) {
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    c = khc_space_from_handle(conf);

    if(!c->name) {
        if(buf && *bufsize > 0)
            buf[0] = L'\0';
        else {
            *bufsize = sizeof(wchar_t);
            rv = KHM_ERROR_TOO_LONG;
        }
    } else {
        size_t cbsize;

        if(FAILED(StringCbLength(c->name, KCONF_MAXCB_NAME, &cbsize)))
            return KHM_ERROR_UNKNOWN;

        cbsize += sizeof(wchar_t);

        if(!buf || cbsize > *bufsize) {
            *bufsize = cbsize;
            rv = KHM_ERROR_TOO_LONG;
        } else {
            StringCbCopy(buf, *bufsize, c->name);
            *bufsize = cbsize;
        }
    }

    return rv;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_get_config_space_parent(khm_handle conf, khm_handle * parent) {
    kconf_conf_space * c;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    c = khc_space_from_handle(conf);

    if(c == conf_root || c->parent == conf_root)
        *parent = NULL;
    else
        *parent = khcint_handle_from_space(c->parent, khc_handle_flags(conf));

    return KHM_ERROR_SUCCESS;
}

/* obtains cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_get_type(khm_handle conf, const wchar_t * value) {
    HKEY hkm = NULL;
    HKEY hku = NULL;
    kconf_conf_space * c;
    khm_int32 rv;
    LONG hr = ERROR_SUCCESS;
    DWORD type = 0;

    if(!khc_is_config_running())
        return KC_NONE;

    if(!khc_is_handle(conf))
        return KC_NONE;

    c = khc_space_from_handle(conf);

    if(!khc_is_machine_handle(conf))
        hku = khcint_space_open_key(c, KHM_PERM_READ);
    hkm = khcint_space_open_key(c, KHM_PERM_READ | KCONF_FLAG_MACHINE);

    if(hku)
        hr = RegQueryValueEx(hku, value, NULL, &type, NULL, NULL);
    if(!hku || hr != ERROR_SUCCESS)
        hr = RegQueryValueEx(hkm, value, NULL, &type, NULL, NULL);
    if(((!hku && !hkm) || hr != ERROR_SUCCESS) && c->schema) {
        int i;

        for(i=0; i<c->nSchema; i++) {
            if(!wcscmp(c->schema[i].name, value)) {
                return c->schema[i].type;
            }
        }

        return KC_NONE;
    }

    switch(type) {
        case REG_MULTI_SZ:
        case REG_SZ:
            rv = KC_STRING;
            break;
        case REG_DWORD:
            rv = KC_INT32;
            break;
        case REG_QWORD:
            rv = KC_INT64;
            break;
        case REG_BINARY:
            rv = KC_BINARY;
            break;
        default:
            rv = KC_NONE;
    }

    return rv;
}

/* obtains cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_value_exists(khm_handle conf, const wchar_t * value) {
    HKEY hku = NULL;
    HKEY hkm = NULL;
    kconf_conf_space * c;
    khm_int32 rv = 0;
    DWORD t;
    int i;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    do {
        c = khc_space_from_handle(conf);

        if (khc_is_user_handle(conf))
            hku = khcint_space_open_key(c, KHM_PERM_READ);
        if (khc_is_machine_handle(conf))
            hkm = khcint_space_open_key(c, KHM_PERM_READ | KCONF_FLAG_MACHINE);

        if(hku && (RegQueryValueEx(hku, value, NULL, &t, NULL, NULL) == ERROR_SUCCESS))
            rv |= KCONF_FLAG_USER;
        if(hkm && (RegQueryValueEx(hkm, value, NULL, &t, NULL, NULL) == ERROR_SUCCESS))
            rv |= KCONF_FLAG_MACHINE;

        if(c->schema && khc_is_schema_handle(conf)) {
            for(i=0; i<c->nSchema; i++) {
                if(!wcscmp(c->schema[i].name, value)) {
                    rv |= KCONF_FLAG_SCHEMA;
                    break;
                }
            }
        }

        /* if the value is not found at this level and the handle is
           shadowed, try the next level down. */
        if (rv == 0 && khc_is_shadowed(conf))
            conf = khc_shadow(conf);
        else
            break;
    } while (conf);

    return rv;
}

/* obtains cs_conf_global */
KHMEXP khm_int32 KHMAPI
khc_remove_value(khm_handle conf, const wchar_t * value, khm_int32 flags) {
    HKEY hku = NULL;
    HKEY hkm = NULL;
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_NOT_FOUND;
    DWORD t;
    LONG l;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    c = khc_space_from_handle(conf);

    if(!khc_is_machine_handle(conf))
        hku = khcint_space_open_key(c, KHM_PERM_READ);
    hkm = khcint_space_open_key(c, KHM_PERM_READ | KCONF_FLAG_MACHINE);

    if((flags == 0 ||
        (flags & KCONF_FLAG_USER)) &&
       hku && (RegQueryValueEx(hku, value, NULL, 
                               &t, NULL, NULL) == ERROR_SUCCESS)) {
        l = RegDeleteValue(hku, value);
        if (l == ERROR_SUCCESS)
            rv = KHM_ERROR_SUCCESS;
        else
            rv = KHM_ERROR_UNKNOWN;
    }
    if((flags == 0 ||
        (flags & KCONF_FLAG_MACHINE)) &&
       hkm && (RegQueryValueEx(hkm, value, NULL, 
                               &t, NULL, NULL) == ERROR_SUCCESS)) {
        l = RegDeleteValue(hkm, value);
        if (l == ERROR_SUCCESS)
            rv = (rv == KHM_ERROR_UNKNOWN)?KHM_ERROR_PARTIAL: 
                KHM_ERROR_SUCCESS;
        else
            rv = (rv == KHM_ERROR_SUCCESS)?KHM_ERROR_PARTIAL:
                KHM_ERROR_UNKNOWN;
    }

    return rv;
}

/* called with cs_conf_global held */
khm_int32
khcint_remove_space(kconf_conf_space * c, khm_int32 flags) {
    kconf_conf_space * cc;
    kconf_conf_space * cn;
    kconf_conf_space * p;

    /* TODO: if this is the last child space and the parent is marked
       for deletion, delete the parent as well. */

    p = TPARENT(c);

    /* We don't allow deleting top level keys.  They are
       predefined. */
#ifdef DEBUG
    assert(p);
#endif
    if (!p)
        return KHM_ERROR_INVALID_OPERATION;

    cc = TFIRSTCHILD(c);
    while (cc) {
        cn = LNEXT(cc);

        khcint_remove_space(cc, flags);

        cc = cn;
    }

    cc = TFIRSTCHILD(c);
    if (!cc && c->refcount == 0) {
        TDELCHILD(p, c);
        khcint_free_space(c);
    } else {
        c->flags |= (flags &
                     (KCONF_SPACE_FLAG_DELETE_M |
                      KCONF_SPACE_FLAG_DELETE_U));

        /* if all the registry spaces have been marked as deleted and
           there is no schema, we should mark the space as deleted as
           well.  Note that ideally we only need to check for stores
           which have data corresponding to this configuration space,
           but this is a bit problematic since we don't monitor the
           registry for changes. */
        if ((c->flags &
             (KCONF_SPACE_FLAG_DELETE_M |
              KCONF_SPACE_FLAG_DELETE_U)) ==
            (KCONF_SPACE_FLAG_DELETE_M |
             KCONF_SPACE_FLAG_DELETE_U) &&
            (!c->schema || c->nSchema == 0))

            c->flags |= KCONF_SPACE_FLAG_DELETED;
    }

    if (c->regpath && p->regpath) {
        HKEY hk;

        if (flags & KCONF_SPACE_FLAG_DELETE_U) {
            hk = khcint_space_open_key(p, KCONF_FLAG_USER);

            if (hk)
                khcint_RegDeleteKey(hk, c->name);
        }
        if (flags & KCONF_SPACE_FLAG_DELETE_M) {
            hk = khcint_space_open_key(p, KCONF_FLAG_MACHINE);

            if (hk)
                khcint_RegDeleteKey(hk, c->name);
        }
    }

    return KHM_ERROR_SUCCESS;
}

/* obtains cs_conf_global */
KHMEXP khm_int32 KHMAPI
khc_remove_space(khm_handle conf) {

    /*
       - mark this space as well as all child spaces as
         'delete-on-close' using flags.  Mark should indicate which
         repository to delete the space from. (user/machine)

       - When each subspace is released, check if it has been marked
         for deletion.  If so, delete the marked spaces as well as
         removing the space from kconf space tree.

       - When removing a subspace from a space, check if the parent
         space has any children left.  If there are none, check if the
         parent space is also marked for deletion.
    */
    kconf_conf_space * c;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_int32 flags = 0;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    c = khc_space_from_handle(conf);

    EnterCriticalSection(&cs_conf_global);

    if (khc_is_machine_handle(conf))
        flags |= KCONF_SPACE_FLAG_DELETE_M;
    if (khc_is_user_handle(conf))
        flags |= KCONF_SPACE_FLAG_DELETE_U;

    rv = khcint_remove_space(c, flags);

    LeaveCriticalSection(&cs_conf_global);

    return rv;
}

/* no locks */
khm_boolean 
khcint_is_valid_name(wchar_t * name)
{
    size_t cbsize;
    if(FAILED(StringCbLength(name, KCONF_MAXCB_NAME, &cbsize)))
        return FALSE;
    return TRUE;
}

/* no locks */
khm_int32 
khcint_validate_schema(const kconf_schema * schema,
                       int begin,
                       int *end)
{
    int i;
    int state = 0;
    int end_found = 0;

    i=begin;
    while(!end_found) {
        switch(state) {
            case 0: /* initial.  this record should start a config space */
                if(!khcint_is_valid_name(schema[i].name) ||
                    schema[i].type != KC_SPACE)
                    return KHM_ERROR_INVALID_PARAM;
                state = 1;
                break;

            case 1: /* we are inside a config space, in the values area */
                if(!khcint_is_valid_name(schema[i].name))
                    return KHM_ERROR_INVALID_PARAM;
                if(schema[i].type == KC_SPACE) {
                    if(KHM_FAILED(khcint_validate_schema(schema, i, &i)))
                        return KHM_ERROR_INVALID_PARAM;
                    state = 2;
                } else if(schema[i].type == KC_ENDSPACE) {
                    end_found = 1;
                    if(end)
                        *end = i;
                } else {
                    if(schema[i].type != KC_STRING &&
                        schema[i].type != KC_INT32 &&
                        schema[i].type != KC_INT64 &&
                        schema[i].type != KC_BINARY)
                        return KHM_ERROR_INVALID_PARAM;
                }
                break;

            case 2: /* we are inside a config space, in the subspace area */
                if(schema[i].type == KC_SPACE) {
                    if(KHM_FAILED(khcint_validate_schema(schema, i, &i)))
                        return KHM_ERROR_INVALID_PARAM;
                } else if(schema[i].type == KC_ENDSPACE) {
                    end_found = 1;
                    if(end)
                        *end = i;
                } else {
                    return KHM_ERROR_INVALID_PARAM;
                }
                break;

            default:
                /* unreachable */
                return KHM_ERROR_INVALID_PARAM;
        }
        i++;
    }

    return KHM_ERROR_SUCCESS;
}

/* obtains cs_conf_handle/cs_conf_global; called with cs_conf_global */
khm_int32 
khcint_load_schema_i(khm_handle parent, const kconf_schema * schema, 
                     int begin, int * end)
{
    int i;
    int state = 0;
    int end_found = 0;
    kconf_conf_space * thisconf = NULL;
    khm_handle h = NULL;

    i=begin;
    while(!end_found) {
        switch(state) {
            case 0: /* initial.  this record should start a config space */
                LeaveCriticalSection(&cs_conf_global);
                if(KHM_FAILED(khc_open_space(parent, schema[i].name, 
                                             KHM_FLAG_CREATE, &h))) {
                    EnterCriticalSection(&cs_conf_global);
                    return KHM_ERROR_INVALID_PARAM;
                }
                EnterCriticalSection(&cs_conf_global);
                thisconf = khc_space_from_handle(h);
                thisconf->schema = schema + (begin + 1);
                thisconf->nSchema = 0;
                state = 1;
                break;

            case 1: /* we are inside a config space, in the values area */
                if(schema[i].type == KC_SPACE) {
                    thisconf->nSchema = i - (begin + 1);
                    if(KHM_FAILED(khcint_load_schema_i(h, schema, i, &i)))
                        return KHM_ERROR_INVALID_PARAM;
                    state = 2;
                } else if(schema[i].type == KC_ENDSPACE) {
                    thisconf->nSchema = i - (begin + 1);
                    end_found = 1;
                    if(end)
                        *end = i;
                    LeaveCriticalSection(&cs_conf_global);
                    khc_close_space(h);
                    EnterCriticalSection(&cs_conf_global);
                }
                break;

            case 2: /* we are inside a config space, in the subspace area */
                if(schema[i].type == KC_SPACE) {
                    if(KHM_FAILED(khcint_load_schema_i(h, schema, i, &i)))
                        return KHM_ERROR_INVALID_PARAM;
                } else if(schema[i].type == KC_ENDSPACE) {
                    end_found = 1;
                    if(end)
                        *end = i;
                    LeaveCriticalSection(&cs_conf_global);
                    khc_close_space(h);
                    EnterCriticalSection(&cs_conf_global);
                } else {
                    return KHM_ERROR_INVALID_PARAM;
                }
                break;

            default:
                /* unreachable */
                return KHM_ERROR_INVALID_PARAM;
        }
        i++;
    }

    return KHM_ERROR_SUCCESS;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_load_schema(khm_handle conf, const kconf_schema * schema)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(conf && !khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    if(KHM_FAILED(khcint_validate_schema(schema, 0, NULL)))
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_conf_global);
    rv = khcint_load_schema_i(conf, schema, 0, NULL);        
    LeaveCriticalSection(&cs_conf_global);

    return rv;
}

/* obtains cs_conf_handle/cs_conf_global; called with cs_conf_global */
khm_int32 
khcint_unload_schema_i(khm_handle parent, const kconf_schema * schema, 
                       int begin, int * end)
{
    int i;
    int state = 0;
    int end_found = 0;
    kconf_conf_space * thisconf = NULL;
    khm_handle h = NULL;

    i=begin;
    while(!end_found) {
        switch(state) {
            case 0: /* initial.  this record should start a config space */
                LeaveCriticalSection(&cs_conf_global);
                if(KHM_FAILED(khc_open_space(parent, schema[i].name, 0, &h))) {
                    EnterCriticalSection(&cs_conf_global);
                    return KHM_ERROR_INVALID_PARAM;
                }
                EnterCriticalSection(&cs_conf_global);
                thisconf = khc_space_from_handle(h);
                if(thisconf->schema == (schema + (begin + 1))) {
                    thisconf->schema = NULL;
                    thisconf->nSchema = 0;
                }
                state = 1;
                break;

            case 1: /* we are inside a config space, in the values area */
                if(schema[i].type == KC_SPACE) {
                    if(KHM_FAILED(khcint_unload_schema_i(h, schema, i, &i)))
                        return KHM_ERROR_INVALID_PARAM;
                    state = 2;
                } else if(schema[i].type == KC_ENDSPACE) {
                    end_found = 1;
                    if(end)
                        *end = i;
                    LeaveCriticalSection(&cs_conf_global);
                    khc_close_space(h);
                    EnterCriticalSection(&cs_conf_global);
                }
                break;

            case 2: /* we are inside a config space, in the subspace area */
                if(schema[i].type == KC_SPACE) {
                    if(KHM_FAILED(khcint_unload_schema_i(h, schema, i, &i)))
                        return KHM_ERROR_INVALID_PARAM;
                } else if(schema[i].type == KC_ENDSPACE) {
                    end_found = 1;
                    if(end)
                        *end = i;
                    LeaveCriticalSection(&cs_conf_global);
                    khc_close_space(h);
                    EnterCriticalSection(&cs_conf_global);
                } else {
                    return KHM_ERROR_INVALID_PARAM;
                }
                break;

            default:
                /* unreachable */
                return KHM_ERROR_INVALID_PARAM;
        }
        i++;
    }

    return KHM_ERROR_SUCCESS;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_unload_schema(khm_handle conf, const kconf_schema * schema)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(conf && !khc_is_handle(conf))
        return KHM_ERROR_INVALID_PARAM;

    if(KHM_FAILED(khcint_validate_schema(schema, 0, NULL)))
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_conf_global);
    rv = khcint_unload_schema_i(conf, schema, 0, NULL);
    LeaveCriticalSection(&cs_conf_global);

    return rv;
}

/* obtaincs cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_enum_subspaces(khm_handle conf,
                   khm_handle prev,
                   khm_handle * next)
{
    kconf_conf_space * s;
    kconf_conf_space * c;
    kconf_conf_space * p;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!khc_is_handle(conf) || next == NULL ||
        (prev != NULL && !khc_is_handle(prev)))
        return KHM_ERROR_INVALID_PARAM;

    s = khc_space_from_handle(conf);

    if(prev == NULL) {
        /* first off, we enumerate all the registry spaces regardless of
        whether the handle is applicable for some registry space or not.
        See notes for khc_begin_enum_subspaces() for reasons as to why
        this is done (notes are in kconfig.h)*/

        /* go through the user hive first */
        {
            HKEY hk_conf;

            hk_conf = khcint_space_open_key(s, 0);
            if(hk_conf) {
                wchar_t name[KCONF_MAXCCH_NAME];
                khm_handle h;
                int idx;

                idx = 0;
                while(RegEnumKey(hk_conf, idx, 
                                 name, ARRAYLENGTH(name)) == ERROR_SUCCESS) {
                    wchar_t * tilde;
                    tilde = wcschr(name, L'~');
                    if (tilde)
                        *tilde = 0;
                    if(KHM_SUCCEEDED(khc_open_space(conf, name, 0, &h)))
                        khc_close_space(h);
                    idx++;
                }
            }
        }

        /* go through the machine hive next */
        {
            HKEY hk_conf;

            hk_conf = khcint_space_open_key(s, KCONF_FLAG_MACHINE);
            if(hk_conf) {
                wchar_t name[KCONF_MAXCCH_NAME];
                khm_handle h;
                int idx;

                idx = 0;
                while(RegEnumKey(hk_conf, idx, 
                                 name, ARRAYLENGTH(name)) == ERROR_SUCCESS) {
                    wchar_t * tilde;
                    tilde = wcschr(name, L'~');
                    if (tilde)
                        *tilde = 0;

                    if(KHM_SUCCEEDED(khc_open_space(conf, name, 
                                                    KCONF_FLAG_MACHINE, &h)))
                        khc_close_space(h);
                    idx++;
                }
            }
        }

        /* don't need to go through schema, because that was already
        done when the schema was loaded. */
    }

    /* at last we are now ready to return the results */
    EnterCriticalSection(&cs_conf_global);
    if(prev == NULL) {
        c = TFIRSTCHILD(s);
        rv = KHM_ERROR_SUCCESS;
    } else {
        p = khc_space_from_handle(prev);
        if(TPARENT(p) == s)
            c = LNEXT(p);
        else
            c = NULL;
    }
    LeaveCriticalSection(&cs_conf_global);

    if(prev != NULL)
        khc_close_space(prev);

    if(c) {
        *next = khcint_handle_from_space(c, khc_handle_flags(conf));
        rv = KHM_ERROR_SUCCESS;
    } else {
        *next = NULL;
        rv = KHM_ERROR_NOT_FOUND;
    }

    return rv;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_write_multi_string(khm_handle conf, const wchar_t * value, wchar_t * buf)
{
    size_t cb;
    wchar_t vbuf[KCONF_MAXCCH_STRING];
    wchar_t *tb;
    khm_int32 rv;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;
    if(!khc_is_handle(conf) || buf == NULL || value == NULL)
        return KHM_ERROR_INVALID_PARAM;

    if(multi_string_to_csv(NULL, &cb, buf) != KHM_ERROR_TOO_LONG)
        return KHM_ERROR_INVALID_PARAM;

    if (cb < sizeof(vbuf))
        tb = vbuf;
    else
        tb = PMALLOC(cb);

    assert(tb != NULL);

    multi_string_to_csv(tb, &cb, buf);
    rv = khc_write_string(conf, value, tb);

    if (tb != vbuf)
        PFREE(tb);
    return rv;
}

/* obtains cs_conf_handle/cs_conf_global */
KHMEXP khm_int32 KHMAPI 
khc_read_multi_string(khm_handle conf, const wchar_t * value, 
                      wchar_t * buf, khm_size * bufsize)
{
    wchar_t vbuf[KCONF_MAXCCH_STRING];
    wchar_t * tb;
    khm_size cbbuf;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!khc_is_config_running())
        return KHM_ERROR_NOT_READY;

    if(!bufsize)
        return KHM_ERROR_INVALID_PARAM;

    rv = khc_read_string(conf, value, NULL, &cbbuf);
    if(rv != KHM_ERROR_TOO_LONG)
        return rv;

    if (cbbuf < sizeof(vbuf))
        tb = vbuf;
    else
        tb = PMALLOC(cbbuf);

    assert(tb != NULL);

    rv = khc_read_string(conf, value, tb, &cbbuf);

    if(KHM_FAILED(rv))
        goto _exit;

    rv = csv_to_multi_string(buf, bufsize, tb);

_exit:
    if (tb != vbuf)
        PFREE(tb);

    return rv;
}
