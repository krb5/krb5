#include "CGSSWindow.h"

const	PaneIDT		text_Output			= 903;

CGSSWindow::CGSSWindow ():
	LWindow ()
{
};

CGSSWindow::CGSSWindow (
	LStream*	inStream):
	LWindow (inStream)
{
}

CGSSWindow::~CGSSWindow ()
{
}

CGSSWindow*
CGSSWindow::CreateGSSWindow (
	ResIDT		inWindowID,
	LCommander*	inSuperCommander)
{
	return (CGSSWindow*) LWindow::CreateWindow (inWindowID, inSuperCommander);
}

CGSSWindow*
CGSSWindow::CreateGSSWindowStream (
	LStream*	inStream)
{
	return new CGSSWindow (inStream);
}

Boolean	
CGSSWindow::ObeyCommand (
	CommandT	inCommand,
	void		*ioParam)
{
	switch (inCommand)
	{
		case cmd_Close:
		// Quit when we close the window
		// We shouldn't get this message because the close box is disabled
			GetSuperCommander () -> ObeyCommand (cmd_Quit);
			return true;
			break;
			
		default:
			return LWindow::ObeyCommand (inCommand, ioParam);
	}
}		
