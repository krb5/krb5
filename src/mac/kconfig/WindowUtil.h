 
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

#ifndef _WindowUtil_
#define _WindowUtil_

#ifndef NULL
#define NULL			0L
#endif

Point PositionTemplate(Rect *BaseRect, ResType, int ResID, int, int);
Point PositionRect(Rect *BaseRect, Rect *VictimRect, int PercentH, int PercentV);
Point PositionRectOnScreen(Rect *VictimRect, int TotallyOnScreen);
void AlignRect(Rect *BaseRect, Rect *VictimRect, int PercentH, int PercentV);

#endif
