#include <CodeFragments.h>
#include <Processes.h>

#define TBALERTID	135
#define TB30ALERTID	136

OSErr __initializeSAPglue(InitBlockPtr ibp);

OSErr __initializeSAPglue(InitBlockPtr ibp)
{
	OSErr					err = noErr;
	short					fileRefNum, theCurrentRes;
	DateTimeRec				goalTimeBomb;
	long					currentTime, goalTimeBombInSecs;
	ProcessSerialNumber		thePSN;
	ProcessInfoRec			thePIR;
	
	/* Do normal init of the shared library */
	__initialize();
	
	/* Start our hack by saving the current resource ref*/
	
	theCurrentRes = CurResFile();
	
	if (ibp->fragLocator.where == kDataForkCFragLocator)
	{ 
		fileRefNum = FSpOpenResFile(ibp->fragLocator.u.onDisk.fileSpec, fsRdPerm);
	
		if ( fileRefNum == -1 )
			err = ResError();
	}
	
	/* We assume that the current process is the one calling us. Good bet */
	err = GetCurrentProcess( &thePSN );
	
	if ( err == noErr )
	{
		GetProcessInformation( &thePSN, &thePIR );
		
		if ( thePIR.processType == 'APPL' )
		{
			switch ( thePIR.processSignature )
			{
				/* Here we case off each application based on its type code */
				case 'MIDA':
					/* This is SAP (supposedly) */
			
					goalTimeBomb.year = 1997;
					goalTimeBomb.month = 6;
					goalTimeBomb.day = 1;
					goalTimeBomb.hour = 0; /* Let's use midnight for simplicity */
					goalTimeBomb.minute = 0;
					goalTimeBomb.second = 0;
					
					DateToSeconds( &goalTimeBomb, &goalTimeBombInSecs );
					
					GetDateTime(&currentTime);
					
					if ( (goalTimeBombInSecs - currentTime) <= 0 )
					{
						StopAlert(TBALERTID, NULL);
						/* if we just reported an error, then the SAP client would continue running. We
							don't want that so instead we'll just call ExitToShell and hope it doesn't
							leave anything hangin. If we just wanted the error, report non-zero */
						//err = -1;
						ExitToShell();
				    }
				    else 
				    	if ( (goalTimeBombInSecs - currentTime) < 1209600 )
						{ /* num seconds in 14 days */
							NoteAlert(TB30ALERTID, NULL);
						}
					break;
				default:
					break;
			}
		}
	}
	if ( fileRefNum != -1 )
		CloseResFile( fileRefNum );
		
	UseResFile( theCurrentRes );
	
	return err;
}

