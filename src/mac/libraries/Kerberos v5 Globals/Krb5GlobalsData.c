/*
 * Definitions for globally shared data used by the Kerberos v5 library
 *
 * $Header$
 */
 
#include "Krb5GlobalsData.h"

UInt32	gKerberos5GlobalsRefCount = 0;
UInt32	gKerberos5SystemDefaultCacheNameModification = 0;
char*	gKerberos5SystemDefaultCacheName = nil;

