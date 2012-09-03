/*
 * Copyright 2011 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifdef WIN32
#include <windows.h>
#define dlltype HMODULE
static char *
dllerror(void) {
    char *amsg;
    LPTSTR msg;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
                      | FORMAT_MESSAGE_FROM_SYSTEM
                      | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, GetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR) &msg, 0, NULL);
    amsg = strdup((const char*) msg);
    LocalFree(msg);
    return amsg;
}
#elif defined(aix)
#include "sys/ldr.h"

struct Dl_info {
  const char* dli_fname;
};

static int
dladdr(void* s, Dl_info* i)
{
    static const size_t bufSize = 4096;
    G__FastAllocString buf(bufSize);
    char* pldi = buf;
    int r;

    r = loadquery(L_GETINFO, pldi, bufSize);
    if (r == -1) {
        i->dli_fname = NULL;
        return 0;
    }

    for (ld_info* ldi = (ld_info*) buf;
         ldi->ldinfo_next;
         ldi += ldi->ldinfo_next) {
        char* textBegin = (char*) ldi->ldinfo_textorg;
        if (textBegin < s) {
            char* textEnd = textBegin + ldi->ldinfo_textsize;
            if (textEnd > s) {
                i->dli_fname = ldi->ldinfo_filename;
                return 1;
            }
        }
    }

    // First is main(), skip.
    ld_info* ldi = (ld_info*) pldi;
    while (ldi->ldinfo_next) {
        pldi += ldi->ldinfo_next;
        ldi = (ld_info*) pldi;

    }

    i->dli_fname = NULL;
    return 0;
}
#else
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#define dlltype void *
#define dllerror() strdup(dlerror())
#endif

int
module_symbol_is_present(const char *modname, const char *symbname)
{
#ifdef WIN32
    return (GetProcAddress(GetModuleHandle(modname), symbname) != NULL ||
            GetProcAddress(GetModuleHandle(NULL), symbname) != NULL);
#else  /* WIN32 */
    void* mod = dlopen(NULL, RTLD_LAZY | RTLD_LOCAL);
    if (mod) {
        void* sym = dlsym(mod, symbname);
        dlclose(mod);
        return sym != NULL;
    }
#endif /* WIN32 */
    return 0;
}

int
module_get_filename_for_symbol(void *addr, char **filename)
{
#ifdef WIN32
    MEMORY_BASIC_INFORMATION info;
    HMODULE mod;
    char tmp[MAX_PATH];

    if (!VirtualQuery(addr, &info, sizeof(info)))
        return 0;
    mod = (HMODULE) info.AllocationBase;

    if (!GetModuleFileNameA(mod, tmp, MAX_PATH))
        return 0;
#else
    const char *tmp;
    Dl_info dlinfo;

    if (!dladdr(addr, &dlinfo))
        return 0;
    tmp = dlinfo.dli_fname;
#endif

    if (filename) {
        *filename = strdup(tmp);
        if (!*filename)
            return 0;
    }

    return 1;
}

void
module_close(void *dll)
{
    if (!dll)
        return;

#ifdef WIN32
    FreeLibrary((dlltype) dll);
#else  /* WIN32 */
    dlclose((dlltype) dll);
#endif /* WIN32 */
}

char *
module_load(const char *filename, const char *symbname,
            int (*shouldload)(void *symb, void *misc, char **err), void *misc,
            void **dll, void **symb)
{
    dlltype intdll = NULL;
    void *  intsym = NULL;
    char *  interr = NULL;

    if (dll)
        *dll = NULL;
    if (symb)
        *symb = NULL;

    /* Open the module library */
#ifdef WIN32
    /* NOTE: DONT_RESOLVE_DLL_REFERENCES is evil. Don't use this in your own
     * code. However, our design pattern avoids all the issues surrounding a
     * more general use of this evil flag. */
    intdll = LoadLibraryEx(filename, NULL, DONT_RESOLVE_DLL_REFERENCES);
#else  /* WIN32 */
    intdll = dlopen(filename, RTLD_LAZY | RTLD_LOCAL);
#endif /* WIN32 */
    if (!intdll)
        return dllerror();

    /* Get the module symbol */
#ifdef WIN32
    intsym = (void *) GetProcAddress(intdll, symbname);
#else /* WIN32 */
    intsym = dlsym(intdll, symbname);
#endif /* WIN32 */
    if (!intsym) {
        module_close(intdll);
        return dllerror();
    }

    /* Figure out whether or not to load this module */
    if (!shouldload(intsym, misc, &interr)) {
        module_close(intdll);
        return interr;
    }

    /* Re-open the module */
    module_close(intdll);
#ifdef WIN32
    intdll = LoadLibrary(filename);
#else  /* WIN32 */
    intdll = dlopen(filename, RTLD_NOW | RTLD_LOCAL);
#endif /* WIN32 */
    if (!intdll) {
        return dllerror();
    }

    /* Get the symbol again */
#ifdef WIN32
    intsym = (void *) GetProcAddress(intdll, symbname);
#else /* WIN32 */
    intsym = dlsym(intdll, symbname);
#endif /* WIN32 */
    if (!intsym) {
        module_close(intdll);
        return dllerror();
    }

    if (dll)
        *dll = intdll;
    if (symb)
        *symb = intsym;
    return NULL;
}
