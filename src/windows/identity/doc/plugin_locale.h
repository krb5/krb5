/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 * Copyright (c) 2007 Secure Endpoints Inc.
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

/*!
\page pi_localization Localization

If a module requires localized resources, it can register the
localized resource libraries with the module manager when it receives
the init_module() callback.  Note that you can only register localized
resource libraries during init_module().

The localized resource library is global to a module.  Each plug-in is
not allowed to define its own localization library, although it is
free to load and use any library as it sees fit.  The module manager
does not manage these libraries for the plug-in.

\section pi_loc_spec Specification of localized resources

In order to register localized resource libraries, a module calls
kmm_set_locale_info().  The \a locales parameter to the function holds
a pointer to an array of ::kmm_module_locale records.  Each record
specifies one language code and a filename of a library that holds the
language resources for that language.

It is recommended that you use the LOCALE_DEF convenience macro when
defining locale records for use with kmm_set_locale_info().  This will
ensure that future changes in the API will only minimally affect your
code.  For example:

\code
kmm_module_locale my_locales[] = {
LOCALE_DEF(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US), L"english.dll", KMM_MLOC_FLAG_DEFAULT),
LOCALE_DEF(MAKELANGID(LANG_DUTCH,SUBLANG_DUTCH), L"dutch.dll", 0),
LOCALE_DEF(MAKELANGID(LANG_SPANISH,SUBLANG_SPANISH_MODERN), L"spanish.dll", 0)
};

int n_locales = sizeof(my_locales)/sizeof(my_locales[0]);

...

kmm_set_locale_info(h_module, my_locales, n_locales);

...
\endcode

See kmm_set_locale_info() and ::kmm_module_locale for more info.

\section pi_loc_how Selection of localized resource library

The module manager searches the array of ::kmm_module_locale objects
passed into the kmm_set_locale_info() function for one that matches
the current user locale (as opposed to the current system locale).  A
record matches the locale if it has the same language ID.  

If a match is found, that library is selected.  Otherwise, the list is
searched for one that is compatible with the current user locale.  A
locale record is compatible with the user locale if the primary
language matches.

If a match is still not found, the first record in the locale array
that has the ::KMM_MLOC_FLAG_DEFAULT flag set will be selected.

If a match is still not found, then the kmm_set_locale_info() will
return ::KHM_ERROR_NOT_FOUND.

\section pi_loc_usage Using localization

The following convenience macros are available for using a module
handle to load resources from the corresponding resource library.
However, for performance reasons, it is advisable to obtain a handle
to the resource library loaded by the module manager using
kmm_get_resource_module() and then use it to access resources using
the regular WIN32 API.

- ::kmm_LoadAccelerators
- ::kmm_LoadBitmap
- ::kmm_LoadCursor
- ::kmm_LoadIcon
- ::kmm_LoadImage
- ::kmm_LoadMenu
- ::kmm_LoadString

*/


