// ===========================================================================
//	GSSSample.h
// ===========================================================================

#pragma once

#include <LApplication.h>
#include "gss.h"

#include "CGSSDocument.h"

class	CGSSSample:
	public LDocApplication
{
public:
						CGSSSample();		// constructor registers all PPobs
	virtual 			~CGSSSample();		// stub destructor
	
		// this overriding function performs application functions
		
	virtual Boolean		ObeyCommand(CommandT inCommand, void* ioParam);	
	
		// this overriding function returns the status of menu items
		
	virtual void		FindCommandStatus(CommandT inCommand,
							Boolean &outEnabled, Boolean &outUsesMark,
							Char16 &outMark, Str255 outName);
			void		ListenToMessage (
							MessageT	inMessage,
							void*		ioParam);
//			void		ShowGSSWindow ();
//			void		HideGSSWindow ();		
			LModelObject*	MakeNewDocument ();
			void		HandleAppleEvent (
							const AppleEvent&	inAppleEvent,
							AppleEvent&			outAEReply,
							AEDesc&				outResult,
							long				inAENumber);
			void		StartUp ();
			void		GetSubModelByPosition (
							DescType		inModelID,
							Int32			inPosition,
							AEDesc			&outToken) const;
							
	
protected:

//	virtual void		Initialize();		// overriding startup functions
	
	private:
		CGSSDocument*	mGSSDocument;	
};