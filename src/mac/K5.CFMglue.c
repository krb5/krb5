#include <krb5.h>

#define kLibraryName "\pK5Library"

/* This code is directly from Technote 1077 */

/*	changed Library name to be hardcoded at the top of the file
	instead in the middle of the code */

#include <CodeFragments.h>

// Private function prototypes

static OSErr Find_Symbol(
	Ptr* pSymAddr,
	Str255 pSymName,
	ProcInfoType pProcInfo);

static pascal OSErr GetSystemArchitecture(OSType *archType);

// Private functions

static pascal OSErr GetSystemArchitecture(OSType *archType)
{
	static long sSysArchitecture = 0; // static so we only Gestalt once.
	OSErr tOSErr = noErr;

	*archType = kAnyCFragArch;   // assume wild architecture

	// If we don't know the system architecture yet...
	if (sSysArchitecture == 0)
	// ...Ask Gestalt what kind of machine we are running on.
	tOSErr = Gestalt(gestaltSysArchitecture, &sSysArchitecture);

	if (tOSErr == noErr) // if no errors
	{
		if (sSysArchitecture == gestalt68k)   // 68k?
			*archType = kMotorola68KCFragArch;   
		else if (sSysArchitecture == gestaltPowerPC) // PPC?
			*archType = kPowerPCCFragArch;       
		else
			tOSErr = gestaltUnknownErr;  // who knows what might be next?
	}
	return tOSErr;
}

static OSErr Find_Symbol(
	Ptr* pSymAddr,
	Str255 pSymName,
	ProcInfoType pProcInfo)
{
	static ConnectionID sCID = 0;
	static OSType sArchType = kAnyCFragArch;
	static OSErr sOSErr = noErr;

	Str255 errMessage;
	Ptr mainAddr;
	SymClass symClass;
	ISAType tISAType;

	if (sArchType == kAnyCFragArch)  // if architecture is undefined...
	{
		sCID = 0;     // ...force (re)connect to library
		sOSErr = GetSystemArchitecture(&sArchType); // determine architecture
		if (sOSErr != noErr)
		return sOSErr; // OOPS!
	}

	if (sArchType == kMotorola68KArch) // ...for CFM68K
		tISAType = kM68kISA | kCFM68kRTA;
	else if (sArchType == kPowerPCArch)  // ...for PPC CFM
		tISAType = kPowerPCISA | kPowerPCRTA;
	else
		sOSErr = gestaltUnknownErr; // who knows what might be next?

	if (sCID == 0) // If we haven't connected to the library yet...
	{
		// NOTE: The library name is hard coded here.
		// I try to isolate the glue code, one file per library.
		// I have had developers pass in the Library name to allow
		// plug-in type support. Additional code has to be added to
		// each entry points glue routine to support multiple or
		// switching connection IDs.
		sOSErr = GetSharedLibrary(kLibraryName, sArchType, kLoadCFrag,
		&sCID, &mainAddr, errMessage);
		if (sOSErr != noErr)
		return sOSErr; // OOPS!
	}

	// If we haven't looked up this symbol yet...
	if ((Ptr) *pSymAddr == (Ptr) kUnresolvedCFragSymbolAddress)    
	{
		// ...look it up now
		sOSErr = FindSymbol(sCID,pSymName,pSymAddr,&symClass);
		if (sOSErr != noErr) // in case of error...
		// ...clear the procedure pointer
		*(Ptr*) &pSymAddr = (Ptr) kUnresolvedSymbolAddress;
#	if !GENERATINGCFM // if this is classic 68k code...
			*pSymAddr = (Ptr)NewRoutineDescriptorTrap((ProcPtr) *pSymAddr,
			pProcInfo, tISAType);  // ...create a routine descriptor...
#	endif
	}
	return sOSErr;
}

/* Public functions & globals */

/* These functions fail silently, anyone have any better ideas? */

/* krb5_auth_con_free */

enum {
	krb5_auth_con_free_ProcInfo = kThinkCStackBased |
	RESULT_SIZE(SIZE_CODE(sizeof(krb5_error_code))) |
	STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(krb5_context))) |
	STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(krb5_auth_context)))
};

krb5_error_code krb5_auth_con_free (
		krb5_context			param1,
		krb5_auth_context		param2))
{
	static krb5_auth_con_free_ProcPtr = kUnresolvedSymbolAddress;

	// if this symbol has not been setup yet...
	if ((Ptr) krb5_auth_con_free_ProcPtr == (Ptr) kUnresolvedSymbolAddress)   
		Find_Symbol((Ptr*) &krb5_auth_con_free_ProcPtr,"\pkrb5_auth_con_free",krb5_auth_con_free_ProcInfo);
	if ((Ptr) krb5_auth_con_free_ProcPtr != (Ptr) kUnresolvedSymbolAddress)
		return krb5_auth_con_free_ProcPtr(param1, param2);
}

/* krb5_auth_con_genaddrs */

enum {
	krb5_auth_con_genaddrs_ProcInfo = kThinkCStackBased |
	RESULT_SIZE(SIZE_CODE(sizeof(krb5_error_code))) |
	STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(krb5_context))) |
	STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(krb5_auth_context))) |
	STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(int))) |
	STACK_ROUTINE_PARAMETER(4, SIZE_CODE(sizeof(int)))
};

krb5_error_code krb5_auth_con_genaddrs (
		krb5_context			param1,
		krb5_auth_context		param2,
		int						param3,
		int						param4))
{
	static krb5_auth_con_genaddrs_ProcPtr = kUnresolvedSymbolAddress;

	// if this symbol has not been setup yet...
	if ((Ptr) krb5_auth_con_genaddrs_ProcPtr == (Ptr) kUnresolvedSymbolAddress)   
		Find_Symbol((Ptr*) &krb5_auth_con_genaddrs_ProcPtr,"\pkrb5_auth_con_genaddrs",krb5_auth_con_genaddrs_ProcInfo);
	if ((Ptr) krb5_auth_con_genaddrs_ProcPtr != (Ptr) kUnresolvedSymbolAddress)
		return krb5_auth_con_genaddrs_ProcPtr(param1, param2, param3, param4);
}

/* krb5_auth_con_getlocalsubkey */

enum {
	krb5_auth_con_getlocalsubkey_ProcInfo = kThinkCStackBased |
	RESULT_SIZE(SIZE_CODE(sizeof(krb5_error_code))) |
	STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(krb5_context))) |
	STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(krb5_auth_context))) |
	STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(krb5_keyblock**)))
};

krb5_error_code krb5_auth_con_getlocalsubkey (
		krb5_context			param1,	
		krb5_auth_context		param2,
		krb5_keyblock**			param3)
{
	static krb5_auth_con_getlocalsubkey_ProcPtr = kUnresolvedSymbolAddress;

	// if this symbol has not been setup yet...
	if ((Ptr) krb5_auth_con_getlocalsubkey_ProcPtr == (Ptr) kUnresolvedSymbolAddress)   
		Find_Symbol((Ptr*) &krb5_auth_con_getlocalsubkey_ProcPtr,"\pkrb5_auth_con_getlocalsubkey",krb5_auth_con_getlocalsubkey_ProcInfo);
	if ((Ptr) krb5_auth_con_getlocalsubkey_ProcPtr != (Ptr) kUnresolvedSymbolAddress)
		return krb5_auth_con_getlocalsubkey_ProcPtr(param1, param2, param3);
}
