#include <CodeFragments.h>
#define TBALERTID	135
#define TB30ALERTID	136

OSErr __initializeSAPglue(InitBlockPtr ibp);

OSErr __initializeSAPglue(InitBlockPtr ibp)
{
	OSErr	err = noErr;
	short	fileRefNum;
	DateTimeRec		goalTimeBomb;
	long			currentTime, goalTimeBombInSecs;
	
	__initialize();
	
	if (ibp->fragLocator.where == kDataForkCFragLocator) {
		fileRefNum = FSpOpenResFile(ibp->fragLocator.u.onDisk.fileSpec, fsRdPerm);
	
		if ( fileRefNum == -1 )
			err = ResError();
	}
	
	goalTimeBomb.year = 1997;
	goalTimeBomb.month = 6;
	goalTimeBomb.day = 1;
	goalTimeBomb.hour = 0; /* Let's use midnight for simplicity */
	goalTimeBomb.minute = 0;
	goalTimeBomb.second = 0;
	
	DateToSeconds( &goalTimeBomb, &goalTimeBombInSecs );
	
	GetDateTime(&currentTime);
	
	if ( (goalTimeBombInSecs - currentTime) <= 0 ) {
		StopAlert(TBALERTID, NULL);
		/* if we just reported an error, then the SAP client would continue running. We
			don't want that so instead we'll just call ExitToShell and hope it doesn't
			leave anything hangin. If we just wanted the error, report non-zero */
		//err = -1;
		ExitToShell();
    } else if ( (goalTimeBombInSecs - currentTime) < 1209600 ) { /* num seconds in 14 days */
		NoteAlert(TB30ALERTID, NULL);
	}

	if ( fileRefNum != -1 )
		CloseResFile( fileRefNum );
	
	return err;
}

