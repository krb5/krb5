/*
 * lib/krb5/os/init_ctx.c
 *
 * Copyright 1994 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * krb5_init_contex()
 */

#define NEED_WINDOWS
#include "k5-int.h"

#ifdef macintosh
static CInfoPBRec	theCatInfo;
static	char		*FileBuffer;
static	int			indexCount;
static FSSpec		theWorkingFile;

static char*
GetDirName(short vrefnum, long dirid, char *dststr)
{
CInfoPBRec	theCatInfo;
FSSpec		theParDir;
char		str[37];
char		*curstr;
OSErr		err;
	// Get info on the directory itself, it's name and it's parent
	theCatInfo.dirInfo.ioCompletion		= NULL;
	theCatInfo.dirInfo.ioNamePtr		= (StringPtr) str;
	theCatInfo.dirInfo.ioVRefNum		= vrefnum;
	theCatInfo.dirInfo.ioFDirIndex		= -1;
	theCatInfo.dirInfo.ioDrDirID		= dirid;
	err = PBGetCatInfoSync(&theCatInfo);

	// If I'm looking at the root directory and I've tried going up once
	// start returning down the call chain
	if (err != noErr || (dirid == 2 && theCatInfo.hFileInfo.ioFlParID == 2))
		return dststr;

	// Construct a file spec for the parent
	curstr = GetDirName(theCatInfo.dirInfo.ioVRefNum, theCatInfo.hFileInfo.ioFlParID, dststr);

	// Copy the pascal string to the end of a C string
	BlockMoveData(&str[1], curstr, str[0]);
	curstr += str[0];
	*curstr++ = ':';
	
	// return a pointer to the end of the string (for someone below to append to)
	return curstr;
}

static void
GetPathname(FSSpec *theFile, char *dststr)
{
FSSpec		theParDir;
char		*curstr;
OSErr		err;

	// Start crawling up the directory path recursivly
	curstr = GetDirName(theFile->vRefNum, theFile->parID, dststr);
	BlockMoveData(&theFile->name[1], curstr, theFile->name[0]);
	curstr += theFile->name[0];
	*curstr = 0;
}

char*
GetMacProfilePathName(void)
{
short	vRefnum;
long	parID;
OSErr	theErr;
FSSpec	krbSpec;
char	pathbuf[255];

	theErr = FindFolder(kOnSystemDisk, kPreferencesFolderType, kDontCreateFolder, &vRefnum, &parID);
	FSMakeFSSpec(vRefnum, parID, "\pkrb5.ini", &krbSpec);
	GetPathname(&krbSpec, &pathbuf);
	return strdup(pathbuf);
}
#endif

/* Set the profile paths in the context. If secure is set to TRUE then 
   do not include user paths (from environment variables, etc.)
*/
static krb5_error_code
os_init_paths(ctx, secure)
	krb5_context ctx;
	krb5_boolean secure;
{
	krb5_error_code	retval = 0;
	char *name = 0;

#if defined(macintosh) || defined(_MSDOS) || defined(_WIN32)
	const char *filenames[2];
#endif

	ctx->profile_secure = secure;

#if defined(_MSDOS) || defined(_WIN32)
    {
        char defname[160];                      /* Default value */
        char krb5conf[160];                     /* Actual value */

        GetWindowsDirectory(defname, sizeof(defname) - 10);
        strcat (defname, "\\");
        strcat (defname, DEFAULT_PROFILE_FILENAME);
        GetPrivateProfileString(INI_FILES, INI_KRB5_CONF, defname,
            krb5conf, sizeof(krb5conf), KERBEROS_INI);
        name = krb5conf;

        filenames[0] = name;
        filenames[1] = 0;
    }

	retval = profile_init(filenames, &ctx->profile);

#else /* _MSDOS || _WIN32 */
#ifdef macintosh
	filenames[0] = GetMacProfilePathName();
	filenames[1] = 0;
	retval = profile_init(filenames, &ctx->profile);
#else
	/*
	 * When the profile routines are later enhanced, we will try
	 * including a config file from user's home directory here.
	 */
        if (!secure) name = getenv("KRB5_CONFIG");
	if(!name) name = DEFAULT_PROFILE_PATH;

	retval = profile_init_path(name, &ctx->profile);
#endif /* macintosh */
#endif /* _MSDOS || _WIN32 */

	if (retval)
	    ctx->profile = 0;

	if (retval == ENOENT)
		retval = KRB5_CONFIG_CANTOPEN;

	if ((retval == PROF_SECTION_NOTOP) ||
	    (retval == PROF_SECTION_SYNTAX) ||
	    (retval == PROF_RELATION_SYNTAX) ||
	    (retval == PROF_EXTRA_CBRACE) ||
	    (retval == PROF_MISSING_OBRACE))
		return KRB5_CONFIG_BADFORMAT;
	    
	return retval;
}

krb5_error_code
krb5_os_init_context(ctx)
	krb5_context ctx;
{
	krb5_os_context os_ctx;
	krb5_error_code	retval = 0;

	if (ctx->os_context)
		return 0;

	os_ctx = malloc(sizeof(struct _krb5_os_context));
	if (!os_ctx)
		return ENOMEM;
	memset(os_ctx, 0, sizeof(struct _krb5_os_context));
	os_ctx->magic = KV5M_OS_CONTEXT;

	ctx->os_context = (void *) os_ctx;

	os_ctx->time_offset = 0;
	os_ctx->usec_offset = 0;
	os_ctx->os_flags = 0;
	os_ctx->default_ccname = 0;

	krb5_cc_set_default_name(ctx, NULL);

	retval = os_init_paths(ctx, FALSE);

	/*
	 * If there's an error in the profile, return an error.  Just
	 * ignoring the error is a Bad Thing (tm).
	 */

	return retval;
}

krb5_error_code
krb5_set_config_files(ctx, filenames)
	krb5_context ctx;
	const char **filenames;
{
	krb5_error_code retval;
	profile_t	profile;
	
	retval = profile_init(filenames, &profile);
	if (retval)
		return retval;

	if (ctx->profile)
		profile_release(ctx->profile);
	ctx->profile = profile;

	return 0;
}

krb5_error_code
krb5_secure_config_files(ctx)
	krb5_context ctx;
{
	krb5_error_code retval;
	
	if (ctx->profile) {
		profile_release(ctx->profile);
		ctx->profile = 0;
	}

	retval = os_init_paths(ctx, TRUE);

	return retval;
}

void
krb5_os_free_context(ctx)
	krb5_context	ctx;
{
	krb5_os_context os_ctx;

	os_ctx = ctx->os_context;
	
	if (!os_ctx)
		return;

	if (os_ctx->default_ccname)
		free(os_ctx->default_ccname);

	os_ctx->magic = 0;
	free(os_ctx);
	ctx->os_context = 0;

	if (ctx->profile)
	    profile_release(ctx->profile);
}
