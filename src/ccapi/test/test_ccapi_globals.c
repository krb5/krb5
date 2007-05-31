#include "test_ccapi_globals.h"

/* GLOBALS */
unsigned int total_failure_count = 0;
unsigned int failure_count = 0;

const char *current_test_name;
const char *current_test_activity;

const char * ccapi_error_strings[30] = {
	
	"ccNoError",						/* 0 */
	"ccIteratorEnd",					/* 201 */
    "ccErrBadParam",
    "ccErrNoMem",
    "ccErrInvalidContext",
    "ccErrInvalidCCache",

    "ccErrInvalidString",				/* 206 */
    "ccErrInvalidCredentials",
    "ccErrInvalidCCacheIterator",
    "ccErrInvalidCredentialsIterator",
    "ccErrInvalidLock",

    "ccErrBadName",						/* 211 */
    "ccErrBadCredentialsVersion",
    "ccErrBadAPIVersion",
    "ccErrContextLocked",
    "ccErrContextUnlocked",

    "ccErrCCacheLocked",				/* 216 */
    "ccErrCCacheUnlocked",
    "ccErrBadLockType",
    "ccErrNeverDefault",
    "ccErrCredentialsNotFound",

    "ccErrCCacheNotFound",				/* 221 */
    "ccErrContextNotFound",
    "ccErrServerUnavailable",
    "ccErrServerInsecure",
    "ccErrServerCantBecomeUID",
    
    "ccErrTimeOffsetNotSet",			/* 226 */
    "ccErrBadInternalMessage",
    "ccErrNotImplemented",
	
};

const char *translate_ccapi_error(cc_int32 err) {
	
	if (err == 0) {
		return ccapi_error_strings[0];
	}
	else if (err >= 201 && err <= 228){
		return ccapi_error_strings[err - 200];
	}
	else {
		return "\"Invalid or private CCAPI error\"";
	}
	
	return "";
}