#include <LWindow.h>

#pragma once

class CGSSWindow:
	public LWindow {
public:
	enum { class_ID = 'GSSw' };
	CGSSWindow ();
	CGSSWindow (
		LStream* inStream);
	~CGSSWindow ();
	static	CGSSWindow*		CreateGSSWindow (
						ResIDT		inWindowID,
						LCommander*	inSuperCommander);
	static	CGSSWindow*		CreateGSSWindowStream (
						LStream*	inStream);
	
	virtual Boolean		ObeyCommand(
							CommandT	inCommand,
							void		*ioParam);
/*			Boolean		AttemptQuit (
							long	inSaveOption);*/
	
};