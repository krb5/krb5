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

/*
 * LDEF to draw text with tabs to specific offsets
 *
 * The offset is set when a tab (9) is encountered.
 * The format is <tab>nnn; where nnn is the decimal offset 
 * from the beginning of the line.
 */
 
#include <Controls.h>
#include <Errors.h>
#include <Fonts.h>
#include <Lists.h>
#include <OSEvents.h>
#include <OSUtils.h>
#include <Packages.h>
#include <QuickDraw.h>
#include <String.h>
#include <Strings.h>
#include <SysEqu.h>
#include <Traps.h>
#include <ToolUtils.h>

/* constants for spacing */

#define kLeftOffset	2
#define kTopOffset	0
#define kIconSpace	2

/* prototypes */

void DrawSICN(Ptr theSICN,short left,short top,GrafPtr drawPort);

/* main LDEF entry point */

pascal void	main(short lMessage, Boolean lSelect, Rect *lRect, Cell lCell,
			     short lDataOffset, short lDataLen, ListHandle lHandle)
{
	FontInfo fontInfo;						/* font information (ascent/descent/etc) */
	ListPtr listPtr;						/* pointer to store dereferenced list */
	SignedByte hStateList, hStateCells;		/* state variables for HGetState/SetState */
	Ptr cellData;							/* points to start of cell data for list */
	short leftDraw,topDraw;					/* left/top offsets from topleft of cell */
	unsigned char *cp, *cp1, *lim;
	unsigned short w; 
	int savefont, savesize;
	GrafPtr current;
	
	#pragma unused (lCell)
	
	/* lock and dereference list mgr handles */
	
	GetPort(&current);
	savefont = current->txFont;
	savesize = current->txSize;
	TextFont(geneva);
	TextSize(9);

	hStateList = HGetState((Handle)lHandle);
	HLock((Handle)lHandle);
	listPtr = *lHandle;
	hStateCells = HGetState(listPtr->cells);
	HLock(listPtr->cells);
	cellData = *(listPtr->cells);
	
	switch (lMessage) {
	  case lInitMsg:
	  	/* we don't need any initialization */
	  	break;

	  case lDrawMsg:
		EraseRect(lRect);
		
	  	if (lDataLen > 0) {
	  	
	  		/* determine starting point for drawing */
	  		
	  		leftDraw =	lRect->left+listPtr->indent.h+kLeftOffset;
	  		/* topDraw =	lRect->top+listPtr->indent.v+kTopOffset; */
	  		topDraw =	lRect->top+kTopOffset;
	  			  		
			GetFontInfo(&fontInfo);

			/*
			 * break text at tabs, setting offset when a tab is encountered.
			 */
			cp = &cellData[lDataOffset];
			lim = &cellData[lDataOffset + lDataLen];
			cp1 = cp;
			w = 0;
			while (cp <= lim) {
				if ((*cp == 9) || (cp >= lim)) {			/* draw previous */
					MoveTo(leftDraw + w, topDraw + fontInfo.ascent);
					if (cp - cp1)
						DrawText(cp1, 0, cp - cp1);
				}
				if (cp >= lim)
					break;
				if (*cp++ == 9) {
					/*
					 * Decode offset
					 */
					w = 0;
					while (cp < lim) {
						if ((*cp >= '0') && (*cp <= '9')) {
							w *= 10;
							w += (*cp - '0');
						}
						if (*cp++ == ';')
							break;
					}
					cp1 = cp;
				}
			}
	  	}

		if (!lSelect)
	  		break;
		
	  case lHiliteMsg:
	  	/* do hilite color */
	  	BitClr((Ptr)HiliteMode,pHiliteBit);
	  	InvertRect(lRect);
	  	break;

	  case lCloseMsg:
	  	break;
	}
	
	TextFont(savefont);
	TextSize(savesize);

	HSetState(listPtr->cells, hStateCells);
	HSetState((Handle)lHandle, hStateList);
}

#ifdef notdef
/* this procedure draws a small icon using CopyBits */

void DrawSICN(Ptr theSICN,short left,short top,GrafPtr drawPort)
{
	BitMap iconMap;
	Rect destRect;

	iconMap.baseAddr = theSICN;
	iconMap.rowBytes = 2;
	SetRect(&iconMap.bounds,0,0,16,16);
	SetRect(&destRect,0,0,16,16);
	OffsetRect(&destRect,left,top);
	CopyBits(&iconMap,&drawPort->portBits,&iconMap.bounds,&destRect,
			srcCopy,nil);
}
#endif
