/*
 *   Copyright (C) 1997 by the Massachusetts Institute of Technology
 *   All rights reserved.
 *
 *   For copying and distribution information, please see the file
 *   COPYRIGHT.
 */

short MacOSErr;

#include <CodeFragments.h>
#include <Processes.h>
/* sarac 02/19/98, added Sound.h for SysBeep() */
#include <Sound.h>

#include "TestTrackLib.h"

#define TBALERTID	135
#define TB30ALERTID	136

struct VersionResourceRecord {
		Byte majorRev;									/* Major revision in BCD*/
		Byte minorRev;									/* Minor vevision in BCD*/
		Byte releaseStage;
		Byte nonReleaseRev;								/* Non-final release #	*/
		short countryCode;								/* Region code			*/
		Str255 shortVersNumStr;							/* Short version number	*/
		Str255 longVersNumStr;							/* Long version number	*/
};

typedef struct VersionResourceRecord VersionResourceRecord, *VersionResourcePtr, **VersionResourceHandle;

OSErr ShlibTestTrack(CFragInitBlockPtr ibp);

OSErr ShlibTestTrack(CFragInitBlockPtr ibp)
{
	OSErr					err = noErr;
	short					fileRefNum, saveRes, processResFile;
	ProcessSerialNumber		thePSN;
	ProcessInfoRec			thePIR;
	FSSpec					currAppSpec;
	VersionResourceHandle	versResource;
	char versionString[256];
	char processSignature[5];
	short len, i;
	
	if ( (Ptr) test_track != (Ptr) kUnresolvedCFragSymbolAddress ) {
		/* Start our hack by saving the current resource ref*/
		
		saveRes = CurResFile();
		
/*		if (ibp->fragLocator.where == kDataForkCFragLocator)
		{ 
			fileRefNum = FSpOpenResFile(ibp->fragLocator.u.onDisk.fileSpec, fsRdPerm);
		
			if ( fileRefNum == -1 )
				err = ResError();
		}*/
		
		/* We assume that the current process is the one calling us. Good bet */
		err = GetCurrentProcess( &thePSN );
		
		if ( err == noErr )
		{
			/* fill in required fields for the ProcessInfoRec */
			thePIR.processInfoLength = sizeof(ProcessInfoRec);
			thePIR.processName = nil;
			thePIR.processAppSpec = &currAppSpec;
			
			GetProcessInformation( &thePSN, &thePIR );
			
			/* copy the processSignature into a string */
		    BlockMoveData (&(thePIR.processSignature),&processSignature,sizeof(OSType));
			processSignature[4] = '\0';
			
/*			processResFile = FSpOpenResFile(&currAppSpec, fsRdPerm);
			err = ResError();*/
			
			if (err == noErr)
			{
				versResource = (VersionResourceHandle)GetResource('vers',1);
				
				if (versResource != nil)
				{
					/* Make a local C-string copy of the short version number string (a Pascall string) */
					HLock((Handle)versResource);
					len = ((**versResource).shortVersNumStr)[0];
					for (i = 1; i <= len; i++)
						versionString[i-1] = ((**versResource).shortVersNumStr)[i];
					versionString[len] = '\0';
					HUnlock((Handle)versResource);
					
					ReleaseResource((Handle)versResource);
				}
			}
			
			if ( thePIR.processType == 'APPL' )
			{
				if (test_track(processSignature, versionString, true, true, 0) == -1) {
				  	SysBeep(10);
				  	SysBeep(10);
				  	
				  	ExitToShell();
				}
			}
		}
		/*if ( fileRefNum != -1 )
			CloseResFile( fileRefNum );*/
			
		UseResFile( saveRes );
	
	}
		
	return err;
}
