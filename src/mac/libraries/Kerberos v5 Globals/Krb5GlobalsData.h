/*
 * Declarations for globally shared data used by Kerberos v5 library
 *
 * $Header$
 */
 
#ifndef __Krb5GlobalsData_h__
#define __Krb5GlobalsData_h__

#include <Types.h>

#if defined(__CFM68K__) && !defined(__USING_STATIC_LIBS__)
#	pragma import on
#endif

extern	UInt32	gKerberos5GlobalsRefCount;
extern	char*	gKerberos5SystemDefaultCacheName;

#if defined(__CFM68K__) && !defined(__USING_STATIC_LIBS__)
#	pragma import reset
#endif

#endif /* __Krb5GlobalsData_h__ */