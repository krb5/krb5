/*
 * WindowUtil.c
 */
extern Point PositionTemplate(Rect *BaseRect, ResType Type, register int ID, int PercentH, int PercentV);
extern Point PositionRect(Rect *BaseRect, Rect *VictimRect, int PercentH, int PercentV);
extern void AlignRect(register Rect *BaseRect, register Rect *VictimRect, int PercentH, int PercentV);
extern Point PositionRectOnScreen(Rect *VictimRect, int TotallyOnScreen);
extern void FitRects(register Rect *BaseRect, register Rect *VictimRect);
extern void FindBestScreen(Rect *WindowRect, Rect *ScreenRect);
