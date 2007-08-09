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

#ifndef __KHIMAIRA_KHDEFS_H__
#define __KHIMAIRA_KHDEFS_H__

/*! \defgroup khdef Core definitions

    Key type definitions used throughout NetIDMgr.
 */
/*@{*/
#include<stddef.h>
#include<limits.h>
#include<wchar.h>

/*!\typedef khm_octet
   \brief A byte (8 bit unsigned)*/

/*!\typedef khm_int16
   \brief A signed 16 bit quantity */

/*!\typedef khm_ui_2
   \brief An unsigned 16 bit quantity */

/*!\typedef khm_int32
   \brief A signed 32 bit quantity */

/*!\typedef khm_ui_4
   \brief An unsigned 32 bit quantity */

/*!\typedef khm_int64
   \brief A signed 64 bit quantity */

/*!\typedef khm_ui_8
   \brief An unsigned 64 bit quantity */

typedef unsigned __int8  khm_octet;

typedef __int16          khm_int16;
typedef unsigned __int16 khm_ui_2;

typedef __int32          khm_int32;
typedef unsigned __int32 khm_ui_4;

typedef __int64          khm_int64;
typedef unsigned __int64 khm_ui_8;

#define VALID_INT_BITS    INT_MAX
#define VALID_UINT_BITS   UINT_MAX

#define KHM_UINT32_MAX 4294967295

#define KHM_INT32_MAX  2147483647
/* this strange form is necessary since - is a unary operator, not a sign
   indicator */
#define KHM_INT32_MIN  (-KHM_INT32_MAX-1)

#define KHM_UINT16_MAX 65535

#define KHM_INT16_MAX 32767
/* this strange form is necessary since - is a unary operator, not a sign
   indicator */
#define KHM_INT16_MIN  (-KHM_INT16_MAX-1)

/*! \brief Generic handle type.

    Handles in NetIDMgr are generic pointers.
*/
typedef void * khm_handle;

/*! \brief The invalid handle

    Just used to indicate that this handle does not point to anything useful.
    Usually returned by a function that returns a handle as a signal that the
    operation failed.
*/
#define KHM_INVALID_HANDLE ((khm_handle) NULL)

/*! \brief Boolean.
*/
typedef khm_int32 khm_boolean;

/*! \brief A size
 */
typedef size_t khm_size;

/*! \typedef ssize_t
    \brief Signed size specifier

    Just a signed version of size_t
 */

#ifndef _SSIZE_T_DEFINED
#ifdef  _WIN64
typedef __int64    ssize_t;
#else
typedef _W64 int   ssize_t;
#endif
#define _SSIZE_T_DEFINED
#endif 

typedef ssize_t khm_ssize;

#if defined(_WIN64)
typedef unsigned __int64 khm_wparm;
/*TODO: is this enough? */
typedef unsigned __int64 khm_lparm;
#elif defined(_WIN32)
typedef unsigned __int32 khm_wparm;
typedef unsigned __int64 khm_lparm;
#else
#error khm_wparm and khm_lparm need to be defined for this platform
#endif

/*!\def KHMAPI 
   \brief Calling convention for NetIDMgr exported functions

   The caling convention for all NetIDMgr exported functions is \b
   __stdcall , unless otherwise noted.
 */

/*!\def KHMEXP
   \brief Export prefix for NetIDMgr exported functions

   When compiling source that exports functions, those exported
   function declarations will be done as follows:

   \code
   __declspec(dllexport) khm_int32 __stdcall function_name(arguments...);
   \endcode

   This eliminates the need for a separate exports definition file.
   However, it doesn't preserve ordinals, but we aren't guaranteeing
   that anyway.

   On the other hand, if a particular function is going to be imported
   from a DLL, it should declared as follows:

   \code
   __declspec(dllimport) khm_int32 __stdcall function_name(arguments...);
   \endcode

   This allows the compiler to properly instrument the import. If the
   function is not declared this way, there will be a stub function
   generated that will just jump to the proper import, generating
   redundant instructions and wasting execution time.

   This macro encapsulates the proper declaration specifier.
 */

#ifdef _WIN32
#define KHMAPI __stdcall

#define KHMEXP_EXP __declspec(dllexport)
#define KHMEXP_IMP __declspec(dllimport)

#define KHMEXP KHMEXP_EXP
#endif

/* Generic permission values */
/*! \brief Generic read permission or request */
#define KHM_PERM_READ       0x100

/*! \brief Generic write permission or request */
#define KHM_PERM_WRITE      0x200

/* Generic flags */
/*! \brief Generic create request

    For most lookup functions, specifying this flag indicates that if
    the requested object is not found it should be created.
*/
#define KHM_FLAG_CREATE     0x1000

/*! \brief Wrap to DWORD boundary

    Returns the smallest integer greater than or equal to the
    parameter that is a multiple of 4.
    
    \note Only use with positive integers. */
#define UBOUND32(d) ((((d)-1)&~3) + 4)

/*! \brief Offset a pointer by a number of bytes

    Given a pointer, returns a void pointer that is a given number of
    bytes offset from the pointer.
 */
#define BYTEOFFSET(p,off) ((void *)(((char *) (p)) + (off)))

/*! \brief Check for powers of 2

    Return TRUE if the operand is a positive power of 2 or 0*/
#define IS_POW2(d) ((d)>=0 && !((d) & ((d) - 1)))

/*! \brief Wrap to upper bound based on start and step size

    Return the smallest element in the series <tt>s, s+t, s+2*t,
    s+3*t, ...</tt> that is greater than or equal to \c v.
*/
#define UBOUNDSS(v,start,step) (((v)<=(start))?(start):(start)+((((v)-((start)+1))/(step))+1)*(step))

/* \brief Length of an array
*/
#define ARRAYLENGTH(x) (sizeof(x)/sizeof(x[0]))

/*! \brief Generic version type*/
typedef struct tag_khm_version {
    khm_ui_2 major;     /*!< Major version number */
    khm_ui_2 minor;     /*!< Minor version number */
    khm_ui_2 patch;     /*!< Patch level */
    khm_ui_2 aux;       /*!< Auxilary level (usually carries a build number) */
} khm_version;

/*@}*/
#endif
