/* Include prototypes for glue functions */
#include <krb5.h>

/* Hardcode library fragment name here */
#define kLibraryName "\pK5Library"
#include <CodeFragments.h>

// Private function prototypes

static OSErr Find_Symbol(
	Ptr* pSymAddr,
	Str255 pSymName,
	ProcInfoType pProcInfo);

static pascal OSErr GetSystemArchitecture(OSType *archType);

/* Public functions & globals */

/* We are providing glue for the following functions, for the benefit of the
	Kerberos v5 telnet plugin:
		krb5_auth_con_free
		krb5_auth_con_genaddrs
		krb5_auth_con_getlocalsubkey
		krb5_auth_con_init

		krb5_auth_con_setaddrs
		krb5_auth_con_setports
		krb5_init_ets

		com_err

		mit_des_ecb_encrypt
		mit_des_init_random_key
		mit_des_key_sched
		mit_des_random_key

		krb5_auth_con_setflags

		krb5_cc_default
		krb5_copy_keyblock
		krb5_free_ap_rep_enc_part
		krb5_free_context
		krb5_free_cred_contents
		krb5_free_creds
		krb5_free_keyblock
		krb5_free_principal
		krb5_fwd_tgt_creds
		krb5_get_credentials
		krb5_init_context

		krb5_mk_req_extended
		krb5_rd_rep
		krb5_sname_to_principal
*/

/* Glue for every function consists of the ProcInfo enum (built from the prototype)
	and a glue function */

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

/* This code is directly from Technote 1077 */

/*	changed Library name to be hardcoded at the top of the file
	instead in the middle of the code */

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
