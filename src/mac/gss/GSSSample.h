// ===========================================================================
//	GSSSample.h
//	©1997 Massachusetts Institute of Technology, All Rights Reserved
//	Based on <PP StarterApp>.h by Metrowerks Inc.
//	Modification by meeroh@mit.edu
//	Started 2/28/97
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

		// this overriding function is called on startup
		// it always creates a new document

	virtual	void		StartUp ();
	
		// this overriding function creates a new document

	virtual	LModelObject*	MakeNewDocument ();
	
		// this overriding function handles incoming AppleEvents
	
	virtual	void		HandleAppleEvent (
							const AppleEvent&	inAppleEvent,
							AppleEvent&			outAEReply,
							AEDesc&				outResult,
							long				inAENumber);
							
	private:
		CGSSDocument*	mGSSDocument;	
};