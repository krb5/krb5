/*
 * Copyright 1988 by the Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#ifndef _ET_H

/* This directory doesn't really know about the krb5 world. The following
   windows defines are usually hidden in k5-config.h. For now I'll just
   place here what is needed from that file. Later we may decide to do
   it differently.
*/
#if defined(_MSDOS) || defined(_WIN32)
#ifdef _MSDOS
	/* Windows 16 specific */
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV __far __export __pascal 
#define KRB5_CALLCONV_C __far __export __cdecl
#define KRB5_DLLIMP
#define INTERFACE   KRB5_CALLCONV
#define INTERFACE_C KRB5_CALLCONV_C
#endif

#ifndef FAR
#define FAR __far
#define NEAR __near
#endif
#else
	/* Windows 32 specific */
#ifdef KRB5_DLL_FILE
#define KRB5_DECLSPEC dllexport
#else
#define KRB5_DECLSPEC dllimport
#endif

#define KRB5_DLLIMP __declspec(KRB5_DECLSPEC)
#define KRB5_CALLCONV __stdcall
#define KRB5_CALLCONV_C __cdecl
#define INTERFACE   KRB5_DLLIMP KRB5_CALLCONV
#define INTERFACE_C KRB5_DLLIMP KRB5_CALLCONV_C

#endif /* Win16 vs Win32 */
	
#define sys_nerr              _sys_nerr
#define sys_errlist           _sys_errlist
int FAR KRB5_CALLCONV MessageBox (void FAR *, const char FAR*, const char FAR*, unsigned int);
#define MB_ICONEXCLAMATION    0x0030
#else
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#define KRB5_DLLIMP
#define INTERFACE
#define INTERFACE_C
#endif /* KRB5_CALLCONV */
#endif

#ifndef FAR
#define FAR
#define NEAR
#endif

#include <errno.h>

struct error_table {
    char const * const * msgs;
    long base;
    int n_msgs;
};
struct et_list {
    struct et_list *next;
    const struct error_table *table;
};
extern struct et_list * _et_list;

#define	ERRCODE_RANGE	8	/* # of bits to shift table number */
#define	BITS_PER_CHAR	6	/* # bits to shift per character in name */

#if (defined(__STDC__) || defined(_WINDOWS)) && !defined(KRB5_NO_PROTOTYPES)
extern const char *error_table_name (long);
#else 
extern const char *error_table_name ();
#endif

#define _ET_H
#endif
