/*
 * Copyright 1991-1994 by The University of Texas at Austin
 * All rights reserved.
 *
 * For infomation contact:
 * Rick Watson
 * University of Texas
 * Computation Center, COM 1
 * Austin, TX 78712
 * r.watson@utexas.edu
 * 512-471-3241
 */
#ifndef _MWERKS
#include <Memory.h>
#include <OSUtils.h>
#include <QuickDraw.h>
#include <Resources.h>
#include <SysEqu.h>
#include <Traps.h>
#include <Types.h>
#include <Windows.h>
#endif
#include "WindowUtil.h"

#if 0
#include "glue.h"
#endif

#define topLeft(r)	(((Point *) &(r))[0])
#define botRight(r)	(((Point *) &(r))[1])
#undef GrayRgn
#define getGrayRgn() (* (RgnHandle*) 0x09EE)

void FindBestScreen(Rect *WindowRect, Rect *ScreenRect);
void FitRects(Rect *BaseRect, Rect *VictimRect);

Point PositionTemplate (Rect *BaseRect, ResType Type, register int ID, 
					   int PercentH, int	PercentV)
{
	Point TopLeft;
	Handle TemplateHand;
	
	TopLeft.v = LMGetMBarHeight() << 1;
	TopLeft.h = TopLeft.v;
	
	TemplateHand = GetResource(Type, ID);
	if (TemplateHand != NULL) {
		
		LoadResource(TemplateHand);
		if (ResError() == noErr) {
			int	TemplateState;
			
			TemplateState = HGetState(TemplateHand);
			HLock(TemplateHand);
			
			TopLeft = PositionRect(BaseRect, (Rect *) *TemplateHand, 
								   PercentH, PercentV);

			HSetState(TemplateHand, TemplateState);
		}	
	}
	
	return (TopLeft);
}


Point PositionRect (Rect *BaseRect, Rect *VictimRect, int PercentH, 
					int PercentV)
{
	char *dummy;
	Point TopLeft;
	BitMap *ScreenBits;
	Rect ScreenRect;
	Rect WindowRect;
	
	ScreenBits = &qd.screenBits;
	
	ScreenRect = ScreenBits->bounds;
	ScreenRect.top += LMGetMBarHeight();
	
	if (BaseRect == NULL) {
		
		WindowRect = ScreenRect;
		
	} else if (BaseRect == (Rect *) -1) {
		WindowPtr				Front;
		
		Front = FrontWindow();
		if (Front != NULL) {
			GrafPtr					OrigPort;
			
			GetPort(&OrigPort);
			SetPort(Front);
			
			WindowRect = Front->portRect;
			
			LocalToGlobal(&topLeft(WindowRect));
			LocalToGlobal(&botRight(WindowRect));
			
			SetPort(OrigPort);
			
		} else
			WindowRect = ScreenRect;
		
	} else if (BaseRect == (Rect *) -2) {
		GrafPtr					OrigPort;
		
		GetPort(&OrigPort);
		if (OrigPort != NULL) {
			
			WindowRect = OrigPort->portRect;
			
			LocalToGlobal(&topLeft(WindowRect));
			LocalToGlobal(&botRight(WindowRect));
			
		} else
			WindowRect = ScreenRect;
		
	} else {
		
		WindowRect = *BaseRect;
		
		LocalToGlobal(&topLeft(WindowRect));
		LocalToGlobal(&botRight(WindowRect));
	}
	
	/*	Make the first attempt to position the window. */
	
	AlignRect(&WindowRect, VictimRect, PercentH, PercentV);
	
	/*	Make certain that the window wonÕt be positioned off-screen.
		If it would have been, find the closest on-screen position for it. */
	
	PositionRectOnScreen(VictimRect, true);
	
	/*	Finish-up the positioning process. */
	
	TopLeft = topLeft(*VictimRect);
	
	return (TopLeft);
}


void AlignRect (register Rect *BaseRect, register Rect *VictimRect, 
				int	PercentH, int PercentV)
{
	Rect FixedRect;
	int	BaseLenH;
	int	BaseLenV;
	int	VictLenH;
	int	VictLenV;
	int DivH;
	int DivV;
	
	DivH = 100 / PercentH;
	DivV = 100 / PercentV;
	
	BaseLenH = (BaseRect->right - BaseRect->left) / DivH;
	BaseLenV = (BaseRect->bottom - BaseRect->top) / DivV;
	
	VictLenH = VictimRect->right - VictimRect->left;
	VictLenV = VictimRect->bottom - VictimRect->top;
	
	FixedRect.left = (BaseRect->left + BaseLenH) - (VictLenH >> 1);
	FixedRect.right = FixedRect.left + VictLenH;
	FixedRect.top = (BaseRect->top + BaseLenV) - (VictLenV >> 1);
	FixedRect.bottom = FixedRect.top + VictLenV;
	
	*VictimRect = FixedRect;
}


Point PositionRectOnScreen (Rect *VictimRect, int TotallyOnScreen)
{
	RgnHandle WindowRgn;
	RgnHandle ResultRgn;
	RgnHandle GrayRgn = getGrayRgn();
	
	WindowRgn = NewRgn();
	ResultRgn = NewRgn();
	if (WindowRgn != NULL && ResultRgn != NULL) {
		int						Reposition;
		
		Reposition = false;
		
		RectRgn(WindowRgn, VictimRect);
		
		if (TotallyOnScreen) {
			
		/*	GrayRgn tends to be set to 0xFFFFFFFF (-1) during startup. */
			
			if ((long) GrayRgn != -1) {
				
				UnionRgn(GrayRgn, WindowRgn, ResultRgn);
				Reposition = EqualRgn(GrayRgn, ResultRgn) == 0;
			}
			
		} else {
			
			if ((long) GrayRgn != -1) {
				
				SectRgn(GrayRgn, WindowRgn, ResultRgn);
				Reposition = EmptyRgn(ResultRgn);
			}
		}
		
		if (Reposition) {
			Rect					ScreenRect;
			
			FindBestScreen(VictimRect, &ScreenRect);
			FitRects(&ScreenRect, VictimRect);
		}
	}
	
	if (WindowRgn != NULL)
		DisposeRgn(WindowRgn);
	if (ResultRgn != NULL)
		DisposeRgn(ResultRgn);
	
	return (topLeft(VictimRect));
}


void FitRects (register Rect *BaseRect, register Rect *VictimRect)
{
	int						VOff;
	int						HOff;
	
	if (VictimRect->top < BaseRect->top)
		VOff = (BaseRect->top - VictimRect->top) + 8;
	else if (VictimRect->bottom > BaseRect->bottom)
		VOff = (BaseRect->bottom - VictimRect->bottom) - 8;
	else
		VOff = 0;
	
	if (VictimRect->left < BaseRect->left)
		HOff = (BaseRect->left - VictimRect->left) + 8;
	else if (VictimRect->right > BaseRect->right)
		HOff = (BaseRect->right - VictimRect->right) - 8;
	else
		HOff = 0;
	
	OffsetRect(VictimRect, HOff, VOff);
}


void FindBestScreen (WindowRect, ScreenRect)
Rect					*WindowRect;
Rect					*ScreenRect;
{
	SysEnvRec				Environment;
	
	SysEnvirons(1, &Environment);
	if (Environment.hasColorQD) {
		GDHandle				GDHand;
		GDHandle				BestGD;
		unsigned long			BestBitCount;
		
		GDHand = GetDeviceList();
		BestGD = NULL;
		BestBitCount = 0;
		
		while (GDHand != NULL) {
			Rect					WindSect;
			unsigned long			BitCount;
			
			WindSect = (*GDHand)->gdRect;
			if (GDHand == GetMainDevice())
				WindSect.top += LMGetMBarHeight();
			
			SectRect(WindowRect, &WindSect, &WindSect);
			if (EmptyRect(&WindSect) == false)
				BitCount = (unsigned long) (WindSect.right - WindSect.left) * (unsigned long) (WindSect.bottom - WindSect.top);
			else
				BitCount = 0;
			
			if (BitCount > BestBitCount) {
				
				BestBitCount = BitCount;
				BestGD = GDHand;
			}
			
			GDHand = GetNextDevice(GDHand);
		}
		
		if (BestGD == NULL)
			BestGD = GetMainDevice();
		
		*ScreenRect = (*BestGD)->gdRect;
	
	} else {
		BitMap *ScreenBits;
		char *dummy;
		
		ScreenBits = &qd.screenBits;

		*ScreenRect = ScreenBits->bounds;
		ScreenRect->top += LMGetMBarHeight();
	}
}


/*
 * Junk so Emacs will set local variables to be compatible with Mac/MPW.
 * Should be at end of file.
 * 
 * Local Variables:
 * tab-width: 4
 * End:
 */

