#include <CodeFragments.h>
#include <Gestalt.h>
#include <Errors.h>

#include "des.h"
#include "deslib.CFMGlue.h"

/* These functions must obey CFM calling conventions. Functions which return
   pointers must return them in D0, not A0 like ThinkC static 68k does.  This way
   we can call CFM functions by pointer from here (if they are called by pointer
   then the compiler can't tell ahead of time to do D0->A0 translation because it
   doesn't know what calling convention the functions use). 
   
   Note that if it is necessary (if you don't use MPWC calling conventions) 
   the D0->A0 translation will be done by the compiler in the places where 
   the application calls these glue routines. */
#pragma d0_pointers on

/* Hardcode library fragment name here */
#define kLibraryName "\pMIT_¥deslib"

/* Private function prototypes */

static OSErr Find_Symbol(
	Ptr* pSymAddr,
	Str255 pSymName,
	ProcInfoType pProcInfo);

static pascal Boolean HaveCFM(void);

static pascal OSErr GetSystemArchitecture(OSType *archType);


/* This code is directly from Technote 1077 */
/* changed Library name to be hardcoded at the top of the file
   instead in the middle of the code */

/* Private functions */

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

static pascal Boolean HaveCFM(void)
{
	long response;
	return ( (Gestalt (gestaltCFMAttr, &response) == noErr) &&
				(((response >> gestaltCFMPresent) & 1) != 0));
}

static OSErr Find_Symbol(
	Ptr* pSymAddr,
	Str255 pSymName,
	ProcInfoType pProcInfo)
{
	static CFragConnectionID sCID = 0;
	static OSType sArchType = kAnyCFragArch;
	static OSErr sOSErr = noErr;

	Str255 errMessage;
	Ptr mainAddr;
	CFragSymbolClass symClass;
	ISAType tISAType;

	if (sArchType == kAnyCFragArch)  // if architecture is undefined...
	{
		sCID = 0;     // ...force (re)connect to library
		sOSErr = GetSystemArchitecture(&sArchType); // determine architecture
		if (sOSErr != noErr)
		return sOSErr; // OOPS!
	}
	
	if (!HaveCFM()) {
		// If we don't have CFM68K, return a reasonable-looking error.
		sOSErr = cfragLibConnErr;
		return sOSErr;
	}

	if (sArchType == kMotorola68KCFragArch) // ...for CFM68K
		tISAType = kM68kISA | kCFM68kRTA;
	else if (sArchType == kPowerPCCFragArch)  // ...for PPC CFM
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
		*(Ptr*) &pSymAddr = (Ptr) kUnresolvedCFragSymbolAddress;
#	if !GENERATINGCFM // if this is classic 68k code...
			*pSymAddr = (Ptr)NewRoutineDescriptorTrap((ProcPtr) *pSymAddr,
			pProcInfo, tISAType);  // ...create a routine descriptor...
#	endif
	}
	return sOSErr;
}


/* CFM Glue Code for exported functions! */

/**** des_random_key ****/
/* int des_random_key(des_cblock *key); */

enum {
  des_random_key_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
};

typedef int (*des_random_key_ProcPtrType)(des_cblock *);
int des_random_key (
    des_cblock * key)
{
  static des_random_key_ProcPtrType des_random_key_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_random_key_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_random_key_ProcPtr, "\pdes_random_key", des_random_key_ProcInfo);
  if((Ptr) des_random_key_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_random_key_ProcPtr(key);
}


/**** des_cbc_cksum ****/
/* unsigned long des_cbc_cksum(des_cblock *in, des_cblock *out, long length, des_key_schedule schedule, des_cblock *ivec); */

enum {
  des_cbc_cksum_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(unsigned long)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(long)))
  | STACK_ROUTINE_PARAMETER(4, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(5, SIZE_CODE(sizeof(des_cblock *)))
};

typedef unsigned long (*des_cbc_cksum_ProcPtrType)(des_cblock *, des_cblock *, long, des_key_schedule, des_cblock *);
unsigned long des_cbc_cksum (
              des_cblock * in,
              des_cblock * out,
              long length,
              des_key_schedule schedule,
              des_cblock * ivec)
{
  static des_cbc_cksum_ProcPtrType des_cbc_cksum_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_cbc_cksum_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_cbc_cksum_ProcPtr, "\pdes_cbc_cksum", des_cbc_cksum_ProcInfo);
  if((Ptr) des_cbc_cksum_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_cbc_cksum_ProcPtr(in, out, length, schedule, ivec);
}


/**** des_is_weak_key ****/
/* int des_is_weak_key(des_cblock key); */

enum {
  des_is_weak_key_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
};

typedef int (*des_is_weak_key_ProcPtrType)(des_cblock);
int des_is_weak_key (
    des_cblock key)
{
  static des_is_weak_key_ProcPtrType des_is_weak_key_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_is_weak_key_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_is_weak_key_ProcPtr, "\pdes_is_weak_key", des_is_weak_key_ProcInfo);
  if((Ptr) des_is_weak_key_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_is_weak_key_ProcPtr(key);
}


/**** des_set_sequence_number ****/
/* void des_set_sequence_number(des_cblock new_sequence_number); */

enum {
  des_set_sequence_number_ProcInfo = kThinkCStackBased
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
};

typedef void (*des_set_sequence_number_ProcPtrType)(des_cblock);
void des_set_sequence_number (
     des_cblock new_sequence_number)
{
  static des_set_sequence_number_ProcPtrType des_set_sequence_number_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_set_sequence_number_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_set_sequence_number_ProcPtr, "\pdes_set_sequence_number", des_set_sequence_number_ProcInfo);
  if((Ptr) des_set_sequence_number_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    des_set_sequence_number_ProcPtr(new_sequence_number);
}


/**** des_fixup_key_parity ****/
/* void des_fixup_key_parity(register des_cblock key); */

enum {
  des_fixup_key_parity_ProcInfo = kThinkCStackBased
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
};

typedef void (*des_fixup_key_parity_ProcPtrType)(register des_cblock);
void des_fixup_key_parity (
     register des_cblock key)
{
  static des_fixup_key_parity_ProcPtrType des_fixup_key_parity_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_fixup_key_parity_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_fixup_key_parity_ProcPtr, "\pdes_fixup_key_parity", des_fixup_key_parity_ProcInfo);
  if((Ptr) des_fixup_key_parity_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    des_fixup_key_parity_ProcPtr(key);
}


/**** des_cbc_encrypt ****/
/* int des_cbc_encrypt(des_cblock *in, des_cblock *out, long length, des_key_schedule schedule, des_cblock ivec, int encrypt); */

enum {
  des_cbc_encrypt_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(long)))
  | STACK_ROUTINE_PARAMETER(4, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(5, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(6, SIZE_CODE(sizeof(int)))
};

typedef int (*des_cbc_encrypt_ProcPtrType)(des_cblock *, des_cblock *, long, des_key_schedule, des_cblock, int);
int des_cbc_encrypt (
    des_cblock * in,
    des_cblock * out,
    long length,
    des_key_schedule schedule,
    des_cblock ivec,
    int encrypt)
{
  static des_cbc_encrypt_ProcPtrType des_cbc_encrypt_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_cbc_encrypt_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_cbc_encrypt_ProcPtr, "\pdes_cbc_encrypt", des_cbc_encrypt_ProcInfo);
  if((Ptr) des_cbc_encrypt_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_cbc_encrypt_ProcPtr(in, out, length, schedule, ivec, encrypt);
}


/**** des_quad_cksum ****/
/* unsigned long des_quad_cksum(unsigned char *in, unsigned long *out, long length, int out_count, des_cblock *c_seed); */

enum {
  des_quad_cksum_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(unsigned long)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(unsigned long *)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(long)))
  | STACK_ROUTINE_PARAMETER(4, SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(5, SIZE_CODE(sizeof(des_cblock *)))
};

typedef unsigned long (*des_quad_cksum_ProcPtrType)(unsigned char *, unsigned long *, long, int, des_cblock *);
unsigned long des_quad_cksum (
              unsigned char * in,
              unsigned long * out,
              long length,
              int out_count,
              des_cblock * c_seed)
{
  static des_quad_cksum_ProcPtrType des_quad_cksum_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_quad_cksum_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_quad_cksum_ProcPtr, "\pdes_quad_cksum", des_quad_cksum_ProcInfo);
  if((Ptr) des_quad_cksum_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_quad_cksum_ProcPtr(in, out, length, out_count, c_seed);
}


/**** des_read_password ****/
/* int des_read_password(des_cblock *k, char *prompt, int verify); */

enum {
  des_read_password_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(char *)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(int)))
};

typedef int (*des_read_password_ProcPtrType)(des_cblock *, char *, int);
int des_read_password (
    des_cblock * k,
    char * prompt,
    int verify)
{
  static des_read_password_ProcPtrType des_read_password_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_read_password_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_read_password_ProcPtr, "\pdes_read_password", des_read_password_ProcInfo);
  if((Ptr) des_read_password_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_read_password_ProcPtr(k, prompt, verify);
}


/**** des_ecb_encrypt ****/
/* int des_ecb_encrypt(des_cblock *in, des_cblock *out, des_key_schedule schedule, int encrypt); */

enum {
  des_ecb_encrypt_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(4, SIZE_CODE(sizeof(int)))
};

typedef int (*des_ecb_encrypt_ProcPtrType)(des_cblock *, des_cblock *, des_key_schedule, int);
int des_ecb_encrypt (
    des_cblock * in,
    des_cblock * out,
    des_key_schedule schedule,
    int encrypt)
{
  static des_ecb_encrypt_ProcPtrType des_ecb_encrypt_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_ecb_encrypt_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_ecb_encrypt_ProcPtr, "\pdes_ecb_encrypt", des_ecb_encrypt_ProcInfo);
  if((Ptr) des_ecb_encrypt_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_ecb_encrypt_ProcPtr(in, out, schedule, encrypt);
}


/**** des_key_sched ****/
/* int des_key_sched(des_cblock k, des_key_schedule schedule); */

enum {
  des_key_sched_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(struct des_ks_struct *)))
};

typedef int (*des_key_sched_ProcPtrType)(des_cblock, des_key_schedule);
int des_key_sched (
    des_cblock k,
    des_key_schedule schedule)
{
  static des_key_sched_ProcPtrType des_key_sched_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_key_sched_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_key_sched_ProcPtr, "\pdes_key_sched", des_key_sched_ProcInfo);
  if((Ptr) des_key_sched_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_key_sched_ProcPtr(k, schedule);
}


/**** des_3pcbc_encrypt ****/
/* void des_3pcbc_encrypt(des_cblock *input, des_cblock *output, long length, des_key_schedule schedule1, des_cblock ivec1, des_key_schedule schedule2, des_cblock ivec2, des_key_schedule schedule3, des_cblock ivec3, int encrypt); */

enum {
  des_3pcbc_encrypt_ProcInfo = kThinkCStackBased
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(long)))
  | STACK_ROUTINE_PARAMETER(4, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(5, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(6, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(7, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(8, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(9, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(10, SIZE_CODE(sizeof(int)))
};

typedef void (*des_3pcbc_encrypt_ProcPtrType)(des_cblock *, des_cblock *, long, des_key_schedule, des_cblock, des_key_schedule, des_cblock, des_key_schedule, des_cblock, int);
void des_3pcbc_encrypt (
     des_cblock * input,
     des_cblock * output,
     long length,
     des_key_schedule schedule1,
     des_cblock ivec1,
     des_key_schedule schedule2,
     des_cblock ivec2,
     des_key_schedule schedule3,
     des_cblock ivec3,
     int encrypt)
{
  static des_3pcbc_encrypt_ProcPtrType des_3pcbc_encrypt_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_3pcbc_encrypt_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_3pcbc_encrypt_ProcPtr, "\pdes_3pcbc_encrypt", des_3pcbc_encrypt_ProcInfo);
  if((Ptr) des_3pcbc_encrypt_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    des_3pcbc_encrypt_ProcPtr(input, output, length, schedule1, ivec1, schedule2, ivec2, schedule3, ivec3, encrypt);
}


/**** make_key_sched ****/
/* int make_key_sched(des_cblock *key, des_key_schedule schedule); */

enum {
  make_key_sched_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(struct des_ks_struct *)))
};

typedef int (*make_key_sched_ProcPtrType)(des_cblock *, des_key_schedule);
int make_key_sched (
    des_cblock * key,
    des_key_schedule schedule)
{
  static make_key_sched_ProcPtrType make_key_sched_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) make_key_sched_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &make_key_sched_ProcPtr, "\pmake_key_sched", make_key_sched_ProcInfo);
  if((Ptr) make_key_sched_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return make_key_sched_ProcPtr(key, schedule);
}


/**** des_crypt ****/
/* char *des_crypt(const char *buf, const char *salt); */

enum {
  des_crypt_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(char *)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(const char *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(const char *)))
};

typedef char * (*des_crypt_ProcPtrType)(const char *, const char *);
char * des_crypt (
       const char * buf,
       const char * salt)
{
  static des_crypt_ProcPtrType des_crypt_ProcPtr = kUnresolvedCFragSymbolAddress;
  
  // if this symbol has not been setup yet...
  if((Ptr) des_crypt_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_crypt_ProcPtr, "\pdes_crypt", des_crypt_ProcInfo);
  if((Ptr) des_crypt_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return(des_crypt_ProcPtr(buf, salt));
}


/**** des_set_random_generator_seed ****/
/* void des_set_random_generator_seed(des_cblock key); */

enum {
  des_set_random_generator_seed_ProcInfo = kThinkCStackBased
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
};

typedef void (*des_set_random_generator_seed_ProcPtrType)(des_cblock);
void des_set_random_generator_seed (
     des_cblock key)
{
  static des_set_random_generator_seed_ProcPtrType des_set_random_generator_seed_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_set_random_generator_seed_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_set_random_generator_seed_ProcPtr, "\pdes_set_random_generator_seed", des_set_random_generator_seed_ProcInfo);
  if((Ptr) des_set_random_generator_seed_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    des_set_random_generator_seed_ProcPtr(key);
}


/**** des_new_random_key ****/
/* int des_new_random_key(des_cblock key); */

enum {
  des_new_random_key_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
};

typedef int (*des_new_random_key_ProcPtrType)(des_cblock);
int des_new_random_key (
    des_cblock key)
{
  static des_new_random_key_ProcPtrType des_new_random_key_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_new_random_key_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_new_random_key_ProcPtr, "\pdes_new_random_key", des_new_random_key_ProcInfo);
  if((Ptr) des_new_random_key_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_new_random_key_ProcPtr(key);
}


/**** des_set_key ****/
/* int des_set_key(des_cblock *key, des_key_schedule schedule); */

enum {
  des_set_key_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(struct des_ks_struct *)))
};

typedef int (*des_set_key_ProcPtrType)(des_cblock *, des_key_schedule);
int des_set_key (
    des_cblock * key,
    des_key_schedule schedule)
{
  static des_set_key_ProcPtrType des_set_key_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_set_key_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_set_key_ProcPtr, "\pdes_set_key", des_set_key_ProcInfo);
  if((Ptr) des_set_key_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_set_key_ProcPtr(key, schedule);
}


/**** des_generate_random_block ****/
/* void des_generate_random_block(des_cblock block); */

enum {
  des_generate_random_block_ProcInfo = kThinkCStackBased
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
};

typedef void (*des_generate_random_block_ProcPtrType)(des_cblock);
void des_generate_random_block (
     des_cblock block)
{
  static des_generate_random_block_ProcPtrType des_generate_random_block_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_generate_random_block_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_generate_random_block_ProcPtr, "\pdes_generate_random_block", des_generate_random_block_ProcInfo);
  if((Ptr) des_generate_random_block_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    des_generate_random_block_ProcPtr(block);
}


/**** des_fcrypt ****/
/* char *des_fcrypt(const char *buf, const char *salt, char *ret); */

enum {
  des_fcrypt_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(char *)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(const char *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(const char *)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(char *)))
};

typedef char * (*des_fcrypt_ProcPtrType)(const char *, const char *, char *);
char * des_fcrypt (
       const char * buf,
       const char * salt,
       char * ret)
{
  static des_fcrypt_ProcPtrType des_fcrypt_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_fcrypt_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_fcrypt_ProcPtr, "\pdes_fcrypt", des_fcrypt_ProcInfo);
  if((Ptr) des_fcrypt_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_fcrypt_ProcPtr(buf, salt, ret);
}


/**** des_read_pw_string ****/
/* int des_read_pw_string(char *s, int max, char *prompt, int verify); */

enum {
  des_read_pw_string_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(char *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(char *)))
  | STACK_ROUTINE_PARAMETER(4, SIZE_CODE(sizeof(int)))
};

typedef int (*des_read_pw_string_ProcPtrType)(char *, int, char *, int);
int des_read_pw_string (
    char * s,
    int max,
    char * prompt,
    int verify)
{
  static des_read_pw_string_ProcPtrType des_read_pw_string_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_read_pw_string_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_read_pw_string_ProcPtr, "\pdes_read_pw_string", des_read_pw_string_ProcInfo);
  if((Ptr) des_read_pw_string_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_read_pw_string_ProcPtr(s, max, prompt, verify);
}


/**** des_cblock_print_file ****/
/* void des_cblock_print_file(des_cblock *x, FILE *fp); */

enum {
  des_cblock_print_file_ProcInfo = kThinkCStackBased
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(FILE *)))
};

typedef void (*des_cblock_print_file_ProcPtrType)(des_cblock *, FILE *);
void des_cblock_print_file (
     des_cblock * x,
     FILE * fp)
{
  static des_cblock_print_file_ProcPtrType des_cblock_print_file_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_cblock_print_file_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_cblock_print_file_ProcPtr, "\pdes_cblock_print_file", des_cblock_print_file_ProcInfo);
  if((Ptr) des_cblock_print_file_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    des_cblock_print_file_ProcPtr(x, fp);
}


/**** des_pcbc_encrypt ****/
/* int des_pcbc_encrypt(des_cblock *in, des_cblock *out, long length, des_key_schedule schedule, des_cblock ivec, int encrypt); */

enum {
  des_pcbc_encrypt_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(long)))
  | STACK_ROUTINE_PARAMETER(4, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(5, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(6, SIZE_CODE(sizeof(int)))
};

typedef int (*des_pcbc_encrypt_ProcPtrType)(des_cblock *, des_cblock *, long, des_key_schedule, des_cblock, int);
int des_pcbc_encrypt (
    des_cblock * in,
    des_cblock * out,
    long length,
    des_key_schedule schedule,
    des_cblock ivec,
    int encrypt)
{
  static des_pcbc_encrypt_ProcPtrType des_pcbc_encrypt_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_pcbc_encrypt_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_pcbc_encrypt_ProcPtr, "\pdes_pcbc_encrypt", des_pcbc_encrypt_ProcInfo);
  if((Ptr) des_pcbc_encrypt_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_pcbc_encrypt_ProcPtr(in, out, length, schedule, ivec, encrypt);
}


/**** des_check_key_parity ****/
/* int des_check_key_parity(register des_cblock key); */

enum {
  des_check_key_parity_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
};

typedef int (*des_check_key_parity_ProcPtrType)(register des_cblock);
int des_check_key_parity (
    register des_cblock key)
{
  static des_check_key_parity_ProcPtrType des_check_key_parity_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_check_key_parity_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_check_key_parity_ProcPtr, "\pdes_check_key_parity", des_check_key_parity_ProcInfo);
  if((Ptr) des_check_key_parity_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_check_key_parity_ProcPtr(key);
}


/**** des_3cbc_encrypt ****/
/* void des_3cbc_encrypt(des_cblock *input,des_cblock *output, long length, des_key_schedule schedule1, des_cblock ivec1, des_key_schedule schedule2, des_cblock ivec2, des_key_schedule schedule3, des_cblock ivec3, int encrypt); */

enum {
  des_3cbc_encrypt_ProcInfo = kThinkCStackBased
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(des_cblock *)))
  | STACK_ROUTINE_PARAMETER(3, SIZE_CODE(sizeof(long)))
  | STACK_ROUTINE_PARAMETER(4, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(5, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(6, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(7, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(8, SIZE_CODE(sizeof(struct des_ks_struct *)))
  | STACK_ROUTINE_PARAMETER(9, SIZE_CODE(sizeof(unsigned char *)))
  | STACK_ROUTINE_PARAMETER(10, SIZE_CODE(sizeof(int)))
};

typedef void (*des_3cbc_encrypt_ProcPtrType)(des_cblock *, des_cblock *, long, des_key_schedule, des_cblock, des_key_schedule, des_cblock, des_key_schedule, des_cblock, int);
void des_3cbc_encrypt (
     des_cblock * input,
     des_cblock * output,
     long length,
     des_key_schedule schedule1,
     des_cblock ivec1,
     des_key_schedule schedule2,
     des_cblock ivec2,
     des_key_schedule schedule3,
     des_cblock ivec3,
     int encrypt)
{
  static des_3cbc_encrypt_ProcPtrType des_3cbc_encrypt_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_3cbc_encrypt_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_3cbc_encrypt_ProcPtr, "\pdes_3cbc_encrypt", des_3cbc_encrypt_ProcInfo);
  if((Ptr) des_3cbc_encrypt_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    des_3cbc_encrypt_ProcPtr(input, output, length, schedule1, ivec1, schedule2, ivec2, schedule3, ivec3, encrypt);
}


/**** des_string_to_key ****/
/* int des_string_to_key(char *str, des_cblock key); */

enum {
  des_string_to_key_ProcInfo = kThinkCStackBased
  | RESULT_SIZE(SIZE_CODE(sizeof(int)))
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(char *)))
  | STACK_ROUTINE_PARAMETER(2, SIZE_CODE(sizeof(unsigned char *)))
};

typedef int (*des_string_to_key_ProcPtrType)(char *, des_cblock);
int des_string_to_key (
    char * str,
    des_cblock key)
{
  static des_string_to_key_ProcPtrType des_string_to_key_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_string_to_key_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_string_to_key_ProcPtr, "\pdes_string_to_key", des_string_to_key_ProcInfo);
  if((Ptr) des_string_to_key_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    return des_string_to_key_ProcPtr(str, key);
}


/**** des_init_random_number_generator ****/
/* void des_init_random_number_generator(des_cblock key); */

enum {
  des_init_random_number_generator_ProcInfo = kThinkCStackBased
  | STACK_ROUTINE_PARAMETER(1, SIZE_CODE(sizeof(unsigned char *)))
};

typedef void (*des_init_random_number_generator_ProcPtrType)(des_cblock);
void des_init_random_number_generator (
     des_cblock key)
{
  static des_init_random_number_generator_ProcPtrType des_init_random_number_generator_ProcPtr = kUnresolvedCFragSymbolAddress;

  // if this symbol has not been setup yet...
  if((Ptr) des_init_random_number_generator_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    Find_Symbol((Ptr *) &des_init_random_number_generator_ProcPtr, "\pdes_init_random_number_generator", des_init_random_number_generator_ProcInfo);
  if((Ptr) des_init_random_number_generator_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    des_init_random_number_generator_ProcPtr(key);
}


Boolean DESLibraryIsPresent(void)
{
	Ptr	symAddr;
	return (Find_Symbol (&symAddr, "\pdes_cbc_encrypt", des_cbc_encrypt_ProcInfo)) == noErr;
}
