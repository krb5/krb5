// ===========================================================================
//	GSSSample.cp
//	©1997 Massachusetts Institute of Technology, All Rights Reserved
//	Based on <PP StarterApp>.cp by Metrowerks Inc.
//	Modification by meeroh@mit.edu
//	Started 2/28/97
// ===========================================================================
//
//	This file contains the code for the GSS Sample application

#include "gss.h"
#include "GSSSample.h"

#include <LGrowZone.h>
#include <LWindow.h>
#include <PP_Messages.h>
#include <PP_Resources.h>
#include <PPobClasses.h>
#include <UDrawingState.h>
#include <UMemoryMgr.h>
#include <URegistrar.h>
#include <LEditField.h>
#include <LActiveScroller.h>

extern "C" {
#include <mit-sock.h>
}

// for mit-sock
OSErr MacOSErr;

#include "CGSSWindow.h"

// put declarations for resource ids (ResIDTs) here

// AppleEvent reference number
const	long		ae_Query			= 4001;

// ===========================================================================
//		€ Main Program
// ===========================================================================

void main(void)
{
									// Set Debugging options
	SetDebugThrow_(debugAction_Alert);
	SetDebugSignal_(debugAction_Alert);

	InitializeHeap(3);				// Initialize Memory Manager
									// Parameter is number of Master Pointer
									//   blocks to allocate
	
									// Initialize standard Toolbox managers
	UQDGlobals::InitializeToolbox(&qd);
	
	new LGrowZone(20000);			// Install a GrowZone function to catch
									//    low memory situations.

	CGSSSample theApp;
	theApp.Run();
}


// ---------------------------------------------------------------------------
//		€ CGSSSample
// ---------------------------------------------------------------------------
//	Constructor

CGSSSample::CGSSSample():
	mGSSDocument (nil)
{
	// Register functions to create core PowerPlant classes
	
	URegistrar::RegisterClass(LButton::class_ID,		(ClassCreatorFunc) LButton::CreateButtonStream);
	URegistrar::RegisterClass(LCaption::class_ID,		(ClassCreatorFunc) LCaption::CreateCaptionStream);
	URegistrar::RegisterClass(LDialogBox::class_ID,		(ClassCreatorFunc) LDialogBox::CreateDialogBoxStream);
	URegistrar::RegisterClass(LEditField::class_ID,		(ClassCreatorFunc) LEditField::CreateEditFieldStream);
	URegistrar::RegisterClass(LPane::class_ID,			(ClassCreatorFunc) LPane::CreatePaneStream);
	URegistrar::RegisterClass(LScroller::class_ID,		(ClassCreatorFunc) LScroller::CreateScrollerStream);
	URegistrar::RegisterClass(LStdControl::class_ID,	(ClassCreatorFunc) LStdControl::CreateStdControlStream);
	URegistrar::RegisterClass(LStdButton::class_ID,		(ClassCreatorFunc) LStdButton::CreateStdButtonStream);
	URegistrar::RegisterClass(LTextEdit::class_ID,		(ClassCreatorFunc) LTextEdit::CreateTextEditStream);
	URegistrar::RegisterClass(LView::class_ID,			(ClassCreatorFunc) LView::CreateViewStream);
	URegistrar::RegisterClass(LWindow::class_ID,		(ClassCreatorFunc) LWindow::CreateWindowStream);

	URegistrar::RegisterClass(LActiveScroller::class_ID,		(ClassCreatorFunc) LActiveScroller::CreateActiveScrollerStream);
	URegistrar::RegisterClass(CGSSWindow::class_ID,				(ClassCreatorFunc) CGSSWindow::CreateGSSWindowStream);

	// Init sokets library	
	init_network (nil, true);
}


// ---------------------------------------------------------------------------
//		€ ~CGSSSample
// ---------------------------------------------------------------------------
//	Destructor
//

CGSSSample::~CGSSSample()
{
}

void
CGSSSample::StartUp ()
{
	MakeNewDocument ();
}

// ---------------------------------------------------------------------------
//		€ ObeyCommand
// ---------------------------------------------------------------------------
//	Respond to commands

Boolean
CGSSSample::ObeyCommand(
	CommandT	inCommand,
	void		*ioParam)
{
	Boolean		cmdHandled = true;

	switch (inCommand) {
	
		// Deal with command messages
		// Any that you don't handle will be passed to LApplication
 			
		case cmd_Close:
		// Quit when the window is closed
			inCommand = cmd_Quit;
			
		default:
			cmdHandled = LDocApplication::ObeyCommand (inCommand, ioParam);
			break;
	}
	
	return cmdHandled;
}

// ---------------------------------------------------------------------------
//		€ FindCommandStatus
// ---------------------------------------------------------------------------
//	This function enables menu commands as needed
//

void
CGSSSample::FindCommandStatus(
	CommandT	inCommand,
	Boolean		&outEnabled,
	Boolean		&outUsesMark,
	Char16		&outMark,
	Str255		outName)
{

	switch (inCommand) {
	
		// Return menu item status according to command messages.
		// Any that you don't handle will be passed to LApplication

		case cmd_Close:
			// Always enabled
			outEnabled = true;
			break;

		default:
			LDocApplication::FindCommandStatus(inCommand, outEnabled,
												outUsesMark, outMark, outName);
			break;
	}
}

// ===========================================================================
// € Apple Event Handlers								Apple Event Handlers €
// ===========================================================================

void
CGSSSample::HandleAppleEvent (
	const AppleEvent&	inAppleEvent,
	AppleEvent&			outAEReply,
	AEDesc&				outResult,
	long				inAENumber)
{
	switch (inAENumber) {

		case ae_Query:
		// Dispatch query to the document
			mGSSDocument -> HandleAppleEvent (inAppleEvent, outAEReply, outResult, inAENumber);
			break;

		default:
			LDocApplication::HandleAppleEvent (inAppleEvent, outAEReply, outResult, inAENumber);
			break;
	}
}

LModelObject*
CGSSSample::MakeNewDocument ()
{
	// There should be only one document!
	SignalIf_ (mGSSDocument != nil);
	
	return (mGSSDocument = new CGSSDocument ());
}

void
CGSSSample::GetSubModelByPosition (
	DescType		inModelID,
	Int32			inPosition,
	AEDesc			&outToken) const
{
	switch (inModelID) {
	
 		case cDocument:
 		// Assume there is only one document and always return it
			PutInToken (mGSSDocument, outToken);
			break;
			
		default:
			LDocApplication::GetSubModelByPosition(inModelID, inPosition,
													outToken);
			break;
	}
}